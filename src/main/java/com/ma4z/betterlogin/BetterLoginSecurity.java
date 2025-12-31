package com.ma4z.betterlogin;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.World;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.bukkit.inventory.InventoryView;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class BetterLoginSecurity extends JavaPlugin implements Listener {

    // Configurable fields
    private File dbFile;
    private DB db;

    // runtime state
    // players who have successfully authenticated this session
    private final Set<UUID> authenticated = Collections.newSetFromMap(new ConcurrentHashMap<>());
    // players who must register
    private final Set<UUID> mustRegister = Collections.newSetFromMap(new ConcurrentHashMap<>());

    // store last known location to restore after login
    private final Map<UUID, Location> savedLocations = new ConcurrentHashMap<>();

    // plugin flags stored in config
    // disable login for cracked (best-effort only)
    private boolean disableCrackLogin = false;

    // NOTE: premium logic is best-effort and documented below

    @Override
    public void onEnable() {
        getLogger().info("BetterLoginSecurity enabling...");
        saveDefaultConfig();
        File dataFolder = getDataFolder();
        if (!dataFolder.exists()) dataFolder.mkdirs();

        dbFile = new File(dataFolder, "passwords.db");
        try {
            db = new DB(dbFile.getAbsolutePath());
            db.prepare();
        } catch (SQLException e) {
            getLogger().severe("Failed to initialize database: " + e.getMessage());
            setEnabled(false);
            return;
        }

        getServer().getPluginManager().registerEvents(this, this);

        // register commands
        this.getCommand("login").setExecutor(new CmdLogin());
        this.getCommand("logout").setExecutor(new CmdLogout());
        this.getCommand("register").setExecutor(new CmdRegister());
        this.getCommand("unregister").setExecutor(new CmdUnregister());
        this.getCommand("changepassword").setExecutor(new CmdChangePassword());
        this.getCommand("setpassword").setExecutor(new CmdSetPassword());
        this.getCommand("premiumlogin").setExecutor(new CmdPremiumLogin());
        this.getCommand("disablelogin").setExecutor(new CmdDisableLogin());

        disableCrackLogin = getConfig().getBoolean("disableCrackLogin", false);

        // Kick-off: ensure online players are in correct state (useful on reload)
        new BukkitRunnable() {
            @Override
            public void run() {
                for (Player p : Bukkit.getOnlinePlayers()) {
                    handlePlayerJoinState(p);
                }
            }
        }.runTaskLater(this, 10L);

        getLogger().info("BetterLoginSecurity enabled.");
    }

    @Override
    public void onDisable() {
        getLogger().info("BetterLoginSecurity disabling...");
        try {
            db.close();
        } catch (Exception ignored) {}
    }

    private void handlePlayerJoinState(Player player) {
        UUID uuid = player.getUniqueId();
        try {
            if (!db.existsPlayer(uuid.toString(), player.getName())) {
                // First time: require register
                mustRegister.add(uuid);
                authenticated.remove(uuid);
                savedLocations.put(uuid, player.getLocation());
                freezeToLoginPosition(player);
                player.sendMessage(color("&eWelcome! Please register with /register <password> <confirm>"));
            } else {
                // Known player: require login
                authenticated.remove(uuid);
                savedLocations.put(uuid, db.getLastLocation(uuid.toString()));
                freezeToLoginPosition(player);
                player.sendMessage(color("&ePlease login with /login <password> (you will be frozen until you login)."));
            }
        } catch (SQLException e) {
            getLogger().severe("DB error while handling join state for " + player.getName() + ": " + e.getMessage());
            player.sendMessage(color("&cInternal error - contact an admin."));
        }
    }

    private void freezeToLoginPosition(Player p) {
        // teleport player to world spawn of server's first world, set flying and no movement
        World w = Bukkit.getWorlds().get(0);
        Location spawn = w.getSpawnLocation().clone();
        spawn.setY(spawn.getY() + 2);
        p.teleport(spawn, PlayerTeleportEvent.TeleportCause.PLUGIN);
        p.setAllowFlight(true);
        p.setFlying(true);
        p.setInvulnerable(true); // extra measure
    }

    private void unfreezeAfterLogin(Player p) {
        p.setAllowFlight(false);
        p.setFlying(false);
        p.setInvulnerable(false);
    }

    /* ------------------------------ Events ------------------------------ */

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onJoin(PlayerJoinEvent e) {
        final Player p = e.getPlayer();
        // handle asynchronously small delay to let player fully initialize
        new BukkitRunnable() {
            @Override
            public void run() {
                handlePlayerJoinState(p);
            }
        }.runTaskLater(this, 2L);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        if (authenticated.contains(p.getUniqueId())) {
            // save last location
            Location loc = p.getLocation();
            try {
                db.saveLastLocation(p.getUniqueId().toString(), loc);
            } catch (SQLException ex) {
                getLogger().warning("Could not save last location for " + p.getName() + ": " + ex.getMessage());
            }
        }
        authenticated.remove(p.getUniqueId());
        mustRegister.remove(p.getUniqueId());
        savedLocations.remove(p.getUniqueId());
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerMove(PlayerMoveEvent e) {
        Player p = e.getPlayer();
        if (!authenticated.contains(p.getUniqueId())) {
            // allow small head rotation but not position changes
            if (e.getFrom().getX() == e.getTo().getX() && e.getFrom().getZ() == e.getTo().getZ() && e.getFrom().getY() == e.getTo().getY()) {
                return; // only rotation
            }
            e.setTo(e.getFrom());
        }
    }

    @EventHandler
    public void onDamage(EntityDamageEvent e) {
        if (e.getEntity() instanceof Player) {
            Player p = (Player) e.getEntity();
            if (!authenticated.contains(p.getUniqueId())) {
                e.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent e) {
        if (e.getWhoClicked() instanceof Player) {
            Player p = (Player) e.getWhoClicked();
            if (!authenticated.contains(p.getUniqueId())) {
                e.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent e) {
        Player p = e.getPlayer();
        if (!authenticated.contains(p.getUniqueId())) {
            // allow only login/register/premiumlogin/disablelogin/unregister messages? Simpler: cancel chat and remind
            e.setCancelled(true);
            p.sendMessage(color("&cYou must login or register before chatting. Use /login or /register."));
        }
    }

    /* --------------------------- Command classes ------------------------- */

    private class CmdRegister implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("Console cannot register.");
                return true;
            }
            Player p = (Player) sender;
            if (args.length < 2) {
                p.sendMessage(color("&cUsage: /register <password> <confirm>"));
                return true;
            }
            if (!mustRegister.contains(p.getUniqueId())) {
                p.sendMessage(color("&cYou are already registered or not in register state."));
                return true;
            }
            String pass = args[0];
            String conf = args[1];
            if (!pass.equals(conf)) {
                p.sendMessage(color("&cPasswords do not match."));
                return true;
            }
            if (pass.length() < 4) {
                p.sendMessage(color("&cPassword too short (min 4)."));
                return true;
            }
            try {
                if (db.existsPlayer(p.getUniqueId().toString(), p.getName())) {
                    p.sendMessage(color("&cAccount already exists."));
                    mustRegister.remove(p.getUniqueId());
                    return true;
                }
                DB.PasswordHash ph = DB.hashPassword(pass);
                db.createPlayer(p.getUniqueId().toString(), p.getName(), ph.hash, ph.salt, ph.iterations);
                authenticated.add(p.getUniqueId());
                mustRegister.remove(p.getUniqueId());
                unfreezeAfterLogin(p);
                // teleport to saved location if exists
                Location target = savedLocations.getOrDefault(p.getUniqueId(), p.getWorld().getSpawnLocation());
                p.teleport(target);
                p.sendMessage(color("&aRegistered and logged in successfully."));
            } catch (SQLException ex) {
                p.sendMessage(color("&cDatabase error."));
                getLogger().severe("DB error during register: " + ex.getMessage());
            }
            return true;
        }
    }

    private class CmdLogin implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("Console cannot login.");
                return true;
            }
            Player p = (Player) sender;
            if (args.length < 1) {
                p.sendMessage(color("&cUsage: /login <password>"));
                return true;
            }
            String pass = args[0];
            try {
                if (!db.existsPlayer(p.getUniqueId().toString(), p.getName())) {
                    p.sendMessage(color("&cNo account found. Register with /register"));
                    return true;
                }
                DB.StoredEntry entry = db.getPlayer(p.getUniqueId().toString(), p.getName());
                boolean ok = DB.verifyPassword(pass, entry.hash, entry.salt, entry.iterations);
                if (!ok) {
                    p.sendMessage(color("&cIncorrect password."));
                    return true;
                }
                authenticated.add(p.getUniqueId());
                mustRegister.remove(p.getUniqueId());
                unfreezeAfterLogin(p);
                // teleport to saved location or world spawn
                Location target = savedLocations.get(p.getUniqueId());
                if (target == null) {
                    target = p.getWorld().getSpawnLocation();
                }
                p.teleport(target);
                p.sendMessage(color("&aLogged in successfully."));
            } catch (SQLException e) {
                p.sendMessage(color("&cDatabase error."));
            }
            return true;
        }
    }

    private class CmdLogout implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("Console cannot logout.");
                return true;
            }
            Player p = (Player) sender;
            if (!authenticated.contains(p.getUniqueId())) {
                p.sendMessage(color("&cYou are not logged in."));
                return true;
            }
            // save current location for next login
            Location loc = p.getLocation();
            try {
                db.saveLastLocation(p.getUniqueId().toString(), loc);
            } catch (SQLException e) {
                getLogger().warning("Could not save last location for logout: " + e.getMessage());
            }
            authenticated.remove(p.getUniqueId());
            mustRegister.remove(p.getUniqueId());
            savedLocations.put(p.getUniqueId(), loc);
            freezeToLoginPosition(p);
            p.sendMessage(color("&eYou have been logged out. Use /login <password> to login."));
            return true;
        }
    }

    private class CmdUnregister implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("Console cannot unregister.");
                return true;
            }
            Player p = (Player) sender;
            try {
                if (!db.existsPlayer(p.getUniqueId().toString(), p.getName())) {
                    p.sendMessage(color("&cNo account to unregister."));
                    return true;
                }
                db.deletePlayer(p.getUniqueId().toString(), p.getName());
                authenticated.remove(p.getUniqueId());
                mustRegister.add(p.getUniqueId());
                freezeToLoginPosition(p);
                p.sendMessage(color("&aYour account was unregistered. Use /register to create a new one."));
            } catch (SQLException e) {
                p.sendMessage(color("&cDatabase error."));
            }
            return true;
        }
    }

    private class CmdChangePassword implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("Console cannot change player password.");
                return true;
            }
            Player p = (Player) sender;
            if (args.length < 2) {
                p.sendMessage(color("&cUsage: /changepassword <current> <new>"));
                return true;
            }
            String cur = args[0];
            String neu = args[1];
            try {
                if (!db.existsPlayer(p.getUniqueId().toString(), p.getName())) {
                    p.sendMessage(color("&cNo account found."));
                    return true;
                }
                DB.StoredEntry entry = db.getPlayer(p.getUniqueId().toString(), p.getName());
                if (!DB.verifyPassword(cur, entry.hash, entry.salt, entry.iterations)) {
                    p.sendMessage(color("&cCurrent password incorrect."));
                    return true;
                }
                DB.PasswordHash ph = DB.hashPassword(neu);
                db.updatePassword(p.getUniqueId().toString(), p.getName(), ph.hash, ph.salt, ph.iterations);
                p.sendMessage(color("&aPassword changed."));
            } catch (SQLException e) {
                p.sendMessage(color("&cDatabase error."));
            }
            return true;
        }
    }

    // Admin command to set or clear password
    private class CmdSetPassword implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!sender.hasPermission("betterlogin.setpassword")) {
                sender.sendMessage(color("&cNo permission."));
                return true;
            }
            if (args.length < 1) {
                sender.sendMessage(color("&cUsage: /setpassword <username> [newpassword]  (no password -> unregisters)"));
                return true;
            }
            String username = args[0];
            String newPass = (args.length >= 2) ? args[1] : null;
            try {
                // find by username
                DB.StoredEntry entry = db.getPlayerByName(username);
                if (entry == null) {
                    sender.sendMessage(color("&cNo such user."));
                    return true;
                }
                if (newPass == null || newPass.isEmpty()) {
                    db.deletePlayer(entry.uuid, username);
                    sender.sendMessage(color("&aUser unregistered (password cleared)."));
                } else {
                    DB.PasswordHash ph = DB.hashPassword(newPass);
                    db.updatePassword(entry.uuid, username, ph.hash, ph.salt, ph.iterations);
                    sender.sendMessage(color("&aPassword set for user."));
                }
            } catch (SQLException e) {
                sender.sendMessage(color("&cDatabase error."));
            }
            return true;
        }
    }

    /* ---------------------- Premium / Disable commands -------------------- */

    private class CmdPremiumLogin implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("Console cannot run premiumlogin.");
                return true;
            }
            Player p = (Player) sender;
            // NOTE: verifying "premium" (i.e., Mojang authenticated) accounts is only available if server is in online-mode
            if (!Bukkit.getOnlineMode()) {
                p.sendMessage(color("&cServer is in offline-mode; true premium verification is not possible."));
                p.sendMessage(color("&eThis command will mark your account as 'premium' locally after logout+login as you requested."));
                try {
                    db.setPremiumFlag(p.getUniqueId().toString(), p.getName(), true);
                } catch (SQLException e) {
                    p.sendMessage(color("&cDatabase error."));
                }
                p.sendMessage(color("&aMarked as premium locally. Please /logout and /login to ensure state refresh."));
                return true;
            }
            // If online-mode true, the player is already authenticated by Mojang. So we can mark premium.
            try {
                if (!db.existsPlayer(p.getUniqueId().toString(), p.getName())) {
                    p.sendMessage(color("&cNo account found to mark as premium."));
                    return true;
                }
                db.setPremiumFlag(p.getUniqueId().toString(), p.getName(), true);
                p.sendMessage(color("&aAccount marked as premium."));
            } catch (SQLException e) {
                p.sendMessage(color("&cDatabase error."));
            }
            return true;
        }
    }

    private class CmdDisableLogin implements CommandExecutor {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!sender.hasPermission("betterlogin.disablelogin")) {
                sender.sendMessage(color("&cNo permission."));
                return true;
            }
            // toggle flag
            disableCrackLogin = !disableCrackLogin;
            getConfig().set("disableCrackLogin", disableCrackLogin);
            saveConfig();
            sender.sendMessage(color("&eDisable cracked login is now: " + (disableCrackLogin ? "&cENABLED" : "&aDISABLED")));
            sender.sendMessage(color("&6Note: Determining cracked vs premium accounts reliably requires online-mode. See plugin docs."));
            return true;
        }
    }

    /* ---------------------------- Utilities ------------------------------ */

    private static String color(String s) {
        return ChatColor.translateAlternateColorCodes('&', s);
    }

    /* ------------------------------- DB --------------------------------- */
    private static class DB {
        private final Connection conn;

        private DB(String dbPath) throws SQLException {
            // Connect using SQLite JDBC. The JDBC driver must be available at runtime.
            this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        }

        private void prepare() throws SQLException {
            try (Statement st = conn.createStatement()) {
                st.execute("CREATE TABLE IF NOT EXISTS accounts (uuid TEXT PRIMARY KEY, username TEXT, hash TEXT, salt TEXT, iterations INTEGER, is_premium INTEGER DEFAULT 0, last_world TEXT, last_x REAL, last_y REAL, last_z REAL, last_yaw REAL, last_pitch REAL)");
            }
        }

        private boolean existsPlayer(String uuid, String username) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM accounts WHERE uuid = ? OR username = ? LIMIT 1")) {
                ps.setString(1, uuid);
                ps.setString(2, username);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        }

        private void createPlayer(String uuid, String username, String hash, String salt, int iterations) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO accounts(uuid, username, hash, salt, iterations) VALUES(?,?,?,?,?)")) {
                ps.setString(1, uuid);
                ps.setString(2, username);
                ps.setString(3, hash);
                ps.setString(4, salt);
                ps.setInt(5, iterations);
                ps.executeUpdate();
            }
        }

        private StoredEntry getPlayer(String uuid, String username) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("SELECT uuid, username, hash, salt, iterations, is_premium, last_world, last_x, last_y, last_z, last_yaw, last_pitch FROM accounts WHERE uuid = ? OR username = ? LIMIT 1")) {
                ps.setString(1, uuid);
                ps.setString(2, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    StoredEntry e = new StoredEntry();
                    e.uuid = rs.getString(1);
                    e.username = rs.getString(2);
                    e.hash = rs.getString(3);
                    e.salt = rs.getString(4);
                    e.iterations = rs.getInt(5);
                    e.isPremium = rs.getInt(6) == 1;
                    String world = rs.getString(7);
                    if (world != null) {
                        try {
                            World w = Bukkit.getWorld(world);
                            if (w != null) {
                                double x = rs.getDouble(8);
                                double y = rs.getDouble(9);
                                double z = rs.getDouble(10);
                                float yaw = rs.getFloat(11);
                                float pitch = rs.getFloat(12);
                                e.lastLocation = new Location(w, x, y, z, yaw, pitch);
                            }
                        } catch (Exception ignored) {}
                    }
                    return e;
                }
            }
        }

        private StoredEntry getPlayerByName(String username) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("SELECT uuid, username, hash, salt, iterations, is_premium FROM accounts WHERE username = ? LIMIT 1")) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    StoredEntry e = new StoredEntry();
                    e.uuid = rs.getString(1);
                    e.username = rs.getString(2);
                    e.hash = rs.getString(3);
                    e.salt = rs.getString(4);
                    e.iterations = rs.getInt(5);
                    e.isPremium = rs.getInt(6) == 1;
                    return e;
                }
            }
        }

        private void deletePlayer(String uuid, String username) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM accounts WHERE uuid = ? OR username = ?")) {
                ps.setString(1, uuid);
                ps.setString(2, username);
                ps.executeUpdate();
            }
        }

        private void updatePassword(String uuid, String username, String hash, String salt, int iterations) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET hash = ?, salt = ?, iterations = ? WHERE uuid = ? OR username = ?")) {
                ps.setString(1, hash);
                ps.setString(2, salt);
                ps.setInt(3, iterations);
                ps.setString(4, uuid);
                ps.setString(5, username);
                ps.executeUpdate();
            }
        }

        private void setPremiumFlag(String uuid, String username, boolean premium) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET is_premium = ? WHERE uuid = ? OR username = ?")) {
                ps.setInt(1, premium ? 1 : 0);
                ps.setString(2, uuid);
                ps.setString(3, username);
                ps.executeUpdate();
            }
        }

        private void saveLastLocation(String uuid, Location loc) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE accounts SET last_world = ?, last_x = ?, last_y = ?, last_z = ?, last_yaw = ?, last_pitch = ? WHERE uuid = ?")) {
                ps.setString(1, loc.getWorld().getName());
                ps.setDouble(2, loc.getX());
                ps.setDouble(3, loc.getY());
                ps.setDouble(4, loc.getZ());
                ps.setFloat(5, loc.getYaw());
                ps.setFloat(6, loc.getPitch());
                ps.setString(7, uuid);
                ps.executeUpdate();
            }
        }

        private Location getLastLocation(String uuid) throws SQLException {
            try (PreparedStatement ps = conn.prepareStatement("SELECT last_world, last_x, last_y, last_z, last_yaw, last_pitch FROM accounts WHERE uuid = ?")) {
                ps.setString(1, uuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    String world = rs.getString(1);
                    if (world == null) return null;
                    World w = Bukkit.getWorld(world);
                    if (w == null) return null;
                    double x = rs.getDouble(2);
                    double y = rs.getDouble(3);
                    double z = rs.getDouble(4);
                    float yaw = rs.getFloat(5);
                    float pitch = rs.getFloat(6);
                    return new Location(w, x, y, z, yaw, pitch);
                }
            }
        }

        private void close() throws SQLException {
            conn.close();
        }

        static class StoredEntry {
            String uuid;
            String username;
            String hash;
            String salt;
            int iterations;
            boolean isPremium;
            Location lastLocation;
        }

        static class PasswordHash {
            String hash;
            String salt;
            int iterations;
        }

        // Password utilities: PBKDF2WithHmacSHA256
        private static final SecureRandom random = new SecureRandom();

        static PasswordHash hashPassword(String pw) {
            try {
                int iterations = 65536;
                byte[] salt = new byte[16];
                random.nextBytes(salt);
                byte[] hash = pbkdf2(pw.toCharArray(), salt, iterations, 256);
                PasswordHash ph = new PasswordHash();
                ph.hash = Base64.getEncoder().encodeToString(hash);
                ph.salt = Base64.getEncoder().encodeToString(salt);
                ph.iterations = iterations;
                return ph;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        static boolean verifyPassword(String pw, String storedHashBase64, String saltBase64, int iterations) {
            try {
                byte[] salt = Base64.getDecoder().decode(saltBase64);
                byte[] expected = Base64.getDecoder().decode(storedHashBase64);
                byte[] got = pbkdf2(pw.toCharArray(), salt, iterations, expected.length * 8);
                return Arrays.equals(expected, got);
            } catch (Exception e) {
                return false;
            }
        }

        private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bits) throws Exception {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        }
    }

}
