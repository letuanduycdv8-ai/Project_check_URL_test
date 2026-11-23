using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Security.Cryptography;

namespace Project_check_URL
{
    public static class UserRepository
    {
        private static readonly string ConnStr =
            ConfigurationManager.ConnectionStrings["Url_login_DB"].ConnectionString;

        private const int SaltSize = 16, HashSize = 32, Iterations = 100000;

        private static string HashPassword(string password)
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            byte[] hash;
            using (var pbkdf2 = new Rfc2898DeriveBytes(
                       password, salt, Iterations, HashAlgorithmName.SHA256))
                hash = pbkdf2.GetBytes(HashSize);

            
            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
        }

        private static bool VerifyPassword(string password, string stored)
        {
            var parts = stored.Split(':');
            byte[] salt = Convert.FromBase64String(parts[0]);
            byte[] expected = Convert.FromBase64String(parts[1]);

            byte[] actual;
            using (var pbkdf2 = new Rfc2898DeriveBytes(
                       password, salt, Iterations, HashAlgorithmName.SHA256))
                actual = pbkdf2.GetBytes(HashSize);

            
            int diff = 0;
            for (int i = 0; i < expected.Length; i++)
                diff |= expected[i] ^ actual[i];
            return diff == 0;
        }

        
        public static bool Register(string username, string password)
        {
            using (var conn = new SqlConnection(ConnStr))
            using (var cmd = new SqlCommand(
                "INSERT INTO Users (Username, PasswordHash) VALUES (@u, @p)", conn))
            {
                cmd.Parameters.AddWithValue("@u", username);
                cmd.Parameters.AddWithValue("@p", HashPassword(password));
                conn.Open();
                try
                {
                    cmd.ExecuteNonQuery();
                    return true;
                }
                catch (SqlException ex) when (ex.Number == 2627 || ex.Number == 2601)
                {
                    return false; 
                }
            }
        }

        
        public static bool Login(string username, string password)
        {
            using (var conn = new SqlConnection(ConnStr))
            using (var cmd = new SqlCommand(
                "SELECT PasswordHash FROM Users WHERE Username = @u", conn))
            {
                cmd.Parameters.AddWithValue("@u", username);
                conn.Open();
                object result = cmd.ExecuteScalar();
                if (result == null) return false;
                return VerifyPassword(password, (string)result);
            }
        }
    }
}