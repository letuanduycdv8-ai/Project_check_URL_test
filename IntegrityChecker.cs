using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Project_check_URL
{
    public static class IntegrityChecker
    {
        public static List<string> VerifyFiles(
            string baseDirectory,
            byte[] manifestBytes)
        {
            var errors = new List<string>();

            // (1) Объявляем HashSet в начале функции
            var listed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string manifest = System.Text.Encoding.UTF8.GetString(
                manifestBytes);

            string root = Path.GetFullPath(baseDirectory)
                .TrimEnd(Path.DirectorySeparatorChar)
                + Path.DirectorySeparatorChar;

            string[] lines = manifest.Split(
                new[] { '\r', '\n' },
                StringSplitOptions.RemoveEmptyEntries);

            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();

                if (line.Length == 0 || line.StartsWith("#"))
                    continue;

                string[] parts = line.Split('|');

                if (parts.Length != 2)
                {
                    errors.Add("Invalid manifest entry: " + line);
                    continue;
                }

                string relativePath = parts[0].Trim();
                string expectedHash = parts[1].Trim();

                try
                {
                    if (Path.IsPathRooted(relativePath))
                    {
                        errors.Add("Invalid file path: " + relativePath);
                        continue;
                    }

                    string fullPath = Path.GetFullPath(
                        Path.Combine(root, relativePath));

                    if (!fullPath.StartsWith(
                        root, StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add("Unsafe file path: " + relativePath);
                        continue;
                    }

                    // (2) Отмечаем файл как допустимый, ПОСЛЕ проверки безопасного пути
                    listed.Add(fullPath);

                    if (!File.Exists(fullPath))
                    {
                        errors.Add("Missing file: " + relativePath);
                        continue;
                    }

                    string actualHash;

                    using (var sha = SHA256.Create())
                    using (var stream = File.OpenRead(fullPath))
                    {
                        byte[] hash = sha.ComputeHash(stream);
                        actualHash = BitConverter.ToString(hash)
                            .Replace("-", "")
                            .ToLowerInvariant();
                    }

                    if (!string.Equals(
                        actualHash,
                        expectedHash,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add("File has been modified: " +
                                   relativePath);
                    }
                }
                catch (Exception ex)
                {
                    errors.Add("Cannot verify " + relativePath +
                               ": " + ex.Message);
                }
            }

            // (3) Ищем посторонние файлы, ПОСЛЕ цикла foreach и ДО return
            var codeExt = new[] { ".exe", ".dll", ".config", ".json" };
            foreach (string f in Directory.EnumerateFiles(
                root, "*", SearchOption.AllDirectories))
            {
                string ext = Path.GetExtension(f).ToLowerInvariant();
                if (Array.IndexOf(codeExt, ext) >= 0 && !listed.Contains(f))
                    errors.Add("Unexpected file: " + f.Substring(root.Length));
            }

            return errors;
        }
    }
}