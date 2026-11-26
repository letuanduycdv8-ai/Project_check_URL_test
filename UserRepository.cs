
using System;
using System.IO;
using System.Data.SQLite;
using System.Security.Cryptography;

namespace Project_check_URL
{
    public static class UserRepository
    {
        private static readonly string DbPath =
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "Project_check_URL",
                "users.db"
            );

        private static readonly string ConnStr =
            "Data Source=" + DbPath + ";Version=3;";

        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const int Iterations = 100000;

        // Automatically initialize database
        static UserRepository()
        {
            InitializeDatabase();
        }

        private static void InitializeDatabase()
        {
            string directory = Path.GetDirectoryName(DbPath);

            Directory.CreateDirectory(directory);

            using (var conn = new SQLiteConnection(ConnStr))
            {
                conn.Open();

                string sql = @"
                    CREATE TABLE IF NOT EXISTS Users
                    (
                        Username TEXT NOT NULL COLLATE NOCASE PRIMARY KEY,
                        PasswordHash TEXT NOT NULL
                    );";

                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }

        // Hash password using PBKDF2 + SHA256
        private static string HashPassword(string password)
        {
            byte[] salt = new byte[SaltSize];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash;

            using (var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                salt,
                Iterations,
                HashAlgorithmName.SHA256))
            {
                hash = pbkdf2.GetBytes(HashSize);
            }

            return Convert.ToBase64String(salt) + ":" +
                   Convert.ToBase64String(hash);
        }

        // Verify password
        private static bool VerifyPassword(
            string password,
            string stored)
        {
            try
            {
                var parts = stored.Split(':');

                if (parts.Length != 2)
                    return false;

                byte[] salt = Convert.FromBase64String(parts[0]);
                byte[] expected = Convert.FromBase64String(parts[1]);

                if (salt.Length != SaltSize ||
                    expected.Length != HashSize)
                    return false;

                byte[] actual;

                using (var pbkdf2 = new Rfc2898DeriveBytes(
                    password,
                    salt,
                    Iterations,
                    HashAlgorithmName.SHA256))
                {
                    actual = pbkdf2.GetBytes(HashSize);
                }

                int diff = 0;

                for (int i = 0; i < expected.Length; i++)
                {
                    diff |= expected[i] ^ actual[i];
                }

                return diff == 0;
            }
            catch (FormatException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        // Register new user
        public static bool Register(
            string username,
            string password)
        {
            string sql = @"
                INSERT OR IGNORE INTO Users
                (Username, PasswordHash)
                VALUES (@u, @p);";

            using (var conn = new SQLiteConnection(ConnStr))
            using (var cmd = new SQLiteCommand(sql, conn))
            {
                cmd.Parameters.AddWithValue("@u", username);
                cmd.Parameters.AddWithValue(
                    "@p", HashPassword(password));

                conn.Open();

                int result = cmd.ExecuteNonQuery();

                // 1 = registered successfully
                // 0 = username already exists
                return result == 1;
            }
        }

        // Login existing user
        public static bool Login(
            string username,
            string password)
        {
            string sql = @"
                SELECT PasswordHash
                FROM Users
                WHERE Username = @u
                LIMIT 1;";

            using (var conn = new SQLiteConnection(ConnStr))
            using (var cmd = new SQLiteCommand(sql, conn))
            {
                cmd.Parameters.AddWithValue("@u", username);

                conn.Open();

                object result = cmd.ExecuteScalar();

                if (result == null || result == DBNull.Value)
                    return false;

                return VerifyPassword(
                    password,
                    Convert.ToString(result));
            }
        }
    }
}
