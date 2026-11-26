using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace Project_check_URL.View
{
    /// <summary>One row for ResultGrid (bind: Criterion, Finding, Level).</summary>
    
    public sealed class CheckFinding
    {
        public CheckFinding(string criterion, string finding, string level)
        {
            Criterion = criterion;
            Finding = finding;
            Level = level;
        }

        public string Criterion { get; }
        public string Finding { get; }
        public string Level { get; }   // "Safe", "Warning" or "Danger"
    }

    internal static class Offline_check
    {
        // ------------------------------------------------------------------
        // Your original code (suffix list extended with a few more entries)
        // ------------------------------------------------------------------
        private static readonly HashSet<string> MultiPartSuffixes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn", "ac.vn",
                "co.uk", "org.uk", "ac.uk", "gov.uk",
                "com.au", "net.au", "org.au",
                "co.jp", "com.br", "co.kr", "com.sg",
                "co.in", "co.nz", "co.za", "com.cn", "com.tw", "com.hk",
                "co.id", "or.id", "web.id", "com.my", "com.mx", "com.tr", "com.ar", "com.co", "com.pe",
                "co.th", "in.th", "com.ph", "com.pk", "com.eg", "com.sa", "com.ua", "com.ng", "co.ke",
                "org.in", "net.in", "gov.in", "org.cn", "net.cn", "gov.cn", "ac.jp", "or.jp", "ne.jp", "go.jp",
                "ac.nz", "org.nz", "co.il", "me.uk", "ltd.uk", "net.uk", "org.au", "edu.au", "gov.au"
            };

        public static string GetRegistrableDomain(string[] labels)
        {
            if (labels.Length <= 2) return string.Join(".", labels);

            string last2 = labels[labels.Length - 2] + "." + labels[labels.Length - 1];
            return MultiPartSuffixes.Contains(last2)? string.Join(".", labels.Skip(labels.Length - 3)): last2;
        }

        public static string ToUnicodeSafe(string[] labels, out bool broken)
        {
            broken = false;
            var idn = new IdnMapping();
            var parts = new List<string>();
            foreach (var l in labels)
            {
                try
                {
                    parts.Add(l.StartsWith("xn--", StringComparison.Ordinal)? idn.GetUnicode(l): l);
                }
                catch (ArgumentException)
                {
                    broken = true;
                    parts.Add(l);
                }
            }
            return string.Join(".", parts);
        }

        // ------------------------------------------------------------------
        // Brand list: add the banks and services your users care about
        // ------------------------------------------------------------------
        public static readonly string[] Brands =
        {
            "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
            "apple.com", "icloud.com", "microsoft.com", "outlook.com", "live.com",
            "paypal.com", "amazon.com", "netflix.com", "github.com", "linkedin.com",
            "dropbox.com", "tiktok.com", "telegram.org", "whatsapp.com", "binance.com",
            "zalo.me", "shopee.vn", "momo.vn", "vietinbank.vn",
            "vietcombank.com.vn", "bidv.com.vn", "techcombank.com.vn",
            "mbbank.com.vn", "acb.com.vn"
        };

        private static readonly HashSet<string> BrandSet =
            new HashSet<string>(Brands, StringComparer.OrdinalIgnoreCase);

        // ------------------------------------------------------------------
        // Loading confusables.txt (call once at startup)
        // ------------------------------------------------------------------
        private static Dictionary<int, string> _map = new Dictionary<int, string>();
        private static Dictionary<string, string> _brandSkeletons =
            new Dictionary<string, string>(StringComparer.Ordinal);

        public static bool IsConfusablesLoaded { get; private set; }

        /// <summary>
        /// Reads confusables.txt into memory. Returns false (and the look-alike check is
        /// skipped) if the file is missing or empty.
        /// </summary>
        public static bool LoadConfusables(string path)
        {
            IsConfusablesLoaded = false;
            if (!File.Exists(path)) return false;

            var map = new Dictionary<int, string>();

            foreach (string raw in File.ReadLines(path, Encoding.UTF8))
            {
                string line = raw.TrimStart('\uFEFF').Trim();
                if (line.Length == 0 || line[0] == '#') continue;

                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);

                // Line format:  0430 ;  0061 ;  MA   # comment
                string[] fields = line.Split(';');
                if (fields.Length < 2) continue;

                int source;
                if (!int.TryParse(fields[0].Trim(), NumberStyles.HexNumber,
                                  CultureInfo.InvariantCulture, out source))
                    continue;

                try
                {
                    var target = new StringBuilder();
                    foreach (string hex in fields[1].Split(new[] { ' ', '\t' },
                                                           StringSplitOptions.RemoveEmptyEntries))
                    {
                        target.Append(char.ConvertFromUtf32(
                            int.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture)));
                    }
                    map[source] = target.ToString();
                }
                catch (FormatException) { /* skip malformed line */ }
                catch (ArgumentOutOfRangeException) { /* skip malformed line */ }
            }

            if (map.Count == 0) return false;
            _map = map;

            var brandSkeletons = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string brand in Brands)
            {
                string sk = LooseSkeleton(brand);
                if (!brandSkeletons.ContainsKey(sk)) brandSkeletons[sk] = brand;
            }
            _brandSkeletons = brandSkeletons;

            IsConfusablesLoaded = true;
            return true;
        }

        // ------------------------------------------------------------------
        // Main entry point: returns rows for ResultGrid
        // ------------------------------------------------------------------
        public static List<CheckFinding> CheckHomograph(Uri uri)
        {
            var findings = new List<CheckFinding>();

            // IP hosts are handled by other checks
            if (uri.HostNameType != UriHostNameType.Dns) 
            {
                findings.Add(CheckIpHost(uri));
                
                return findings;
            }

            string host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
            string[] labels = host.Split('.');

            bool broken;
            string decoded = ToUnicodeSafe(labels, out broken);
            string[] decodedLabels = decoded.Split('.');
            bool hasIdn = labels.Any(l => l.StartsWith("xn--", StringComparison.Ordinal));

            // 1) Punycode
            if (broken)
                findings.Add(new CheckFinding("Punycode (IDN)",
                    "A label starts with 'xn--' but cannot be decoded", "Warning"));
            else if (hasIdn)
                findings.Add(new CheckFinding("Punycode (IDN)",
                    "Domain uses international characters. Decoded: " + decoded, "Warning"));
            else
                findings.Add(new CheckFinding("Punycode (IDN)", "No punycode labels", "Safe"));

            // 2) Mixed writing systems inside one label
            string mixed = FindMixedScriptLabel(decodedLabels);
            findings.Add(mixed != null
                ? new CheckFinding("Mixed writing systems", mixed, "Danger")
                : new CheckFinding("Mixed writing systems", "Each label uses a single writing system", "Safe"));

            // 3) Look-alike of a known brand (needs confusables.txt)
            if (!IsConfusablesLoaded)
            {
                findings.Add(new CheckFinding("Brand impersonation",
                    "confusables.txt not loaded, check skipped", "Warning"));
            }
            else
            {
                try
                {
                    findings.Add(CheckBrandLookalike(decodedLabels));
                }
                catch (ArgumentException)
                {
                    findings.Add(new CheckFinding("Brand impersonation",
                        "Domain contains characters that cannot be normalized", "Warning"));
                }
            }

            return findings;
        }

        private static CheckFinding CheckBrandLookalike(string[] decodedLabels)
        {
            string registrable = GetRegistrableDomain(decodedLabels);

            if (BrandSet.Contains(registrable))
                return new CheckFinding("Brand impersonation",
                    "Official domain of a known brand (" + registrable + ")", "Safe");

            string skeleton = LooseSkeleton(registrable);

            // Same skeleton: looks identical to a brand but is a different string
            string brand;
            if (_brandSkeletons.TryGetValue(skeleton, out brand))
                return new CheckFinding("Brand impersonation",
                    "'" + registrable + "' looks identical to " + brand, "Danger");

            // One edit away from a brand skeleton: typosquatting
            if (skeleton.Length >= 6)
            {
                foreach (KeyValuePair<string, string> kv in _brandSkeletons)
                {
                    // very short brand names (acb, x...) would flag too many innocent domains
                    if (kv.Value.Split('.')[0].Length >= 5 &&
                        Math.Abs(kv.Key.Length - skeleton.Length) <= 1 &&
                        EditDistance(skeleton, kv.Key) == 1)
                        return new CheckFinding("Brand impersonation",
                            "'" + registrable + "' is one character away from " + kv.Value, "Warning");
                }
            }

            return new CheckFinding("Brand impersonation", "No resemblance to known brands", "Safe");
        }
        // IP local : 
        private static CheckFinding CheckIpHost(Uri uri)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(uri.DnsSafeHost, out ip))
                return new CheckFinding("IP address",
                    "Host is not a domain name and cannot be read as an IP address", "Warning");

            if (!ClientMng.IsPublicAddress(ip))
                return new CheckFinding("IP address",
                    "Link points to a private or reserved address (" + ip + "), not to a public website", "Danger");

            return new CheckFinding("IP address",
                "Link uses a raw IP address (" + ip + ") instead of a domain name", "Warning");
        }

        // ------------------------------------------------------------------
        // Skeleton (UTS #39): NFD -> map confusables -> NFD.
        // "Loose" also lowercases and drops combining marks so that diacritics
        // cannot be used to dodge the comparison.
        // ------------------------------------------------------------------
        public static string LooseSkeleton(string s)
        {
            string nfd = s.ToLowerInvariant().Normalize(NormalizationForm.FormD);

            var mapped = new StringBuilder(nfd.Length);
            foreach (int cp in CodePoints(nfd))
            {
                string replacement;
                if (_map.TryGetValue(cp, out replacement)) mapped.Append(replacement);
                else mapped.Append(char.ConvertFromUtf32(cp));
            }

            string again = mapped.ToString().Normalize(NormalizationForm.FormD);

            var result = new StringBuilder(again.Length);
            foreach (char c in again)
            {
                if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                    result.Append(c);
            }
            return result.ToString().ToLowerInvariant();
        }

        private static IEnumerable<int> CodePoints(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    yield return char.ConvertToUtf32(s[i], s[i + 1]);
                    i++;
                }
                else
                {
                    yield return s[i];
                }
            }
        }

        // ------------------------------------------------------------------
        // Writing-system detection
        // ------------------------------------------------------------------
        private enum Script
        {
            Latin, Cyrillic, Greek, Armenian, Hebrew, Arabic, Thai,
            Han, Hiragana, Katakana, Hangul, Other
        }

        /// <summary>Returns null for characters that belong to no particular script (digits, '-', marks).</summary>
        private static Script? ScriptOf(int c)
        {
            if (c >= 0xD800 && c <= 0xDFFF) return Script.Other;

            switch (CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(c), 0))
            {
                case UnicodeCategory.NonSpacingMark:
                case UnicodeCategory.SpacingCombiningMark:
                case UnicodeCategory.EnclosingMark:
                case UnicodeCategory.DecimalDigitNumber:
                case UnicodeCategory.DashPunctuation:
                case UnicodeCategory.ConnectorPunctuation:
                case UnicodeCategory.OtherPunctuation:
                case UnicodeCategory.Format:
                    return null;
            }

            if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0xAA || c == 0xBA ||
                (c >= 0xC0 && c <= 0x2AF && c != 0xD7 && c != 0xF7) ||
                (c >= 0x1E00 && c <= 0x1EFF) || (c >= 0x2C60 && c <= 0x2C7F) ||
                (c >= 0xA720 && c <= 0xA7FF) || (c >= 0xFF21 && c <= 0xFF5A))
                return Script.Latin;

            if ((c >= 0x400 && c <= 0x52F) || (c >= 0x1C80 && c <= 0x1C8F) ||
                (c >= 0x2DE0 && c <= 0x2DFF) || (c >= 0xA640 && c <= 0xA69F))
                return Script.Cyrillic;

            if ((c >= 0x370 && c <= 0x3FF) || (c >= 0x1F00 && c <= 0x1FFF)) return Script.Greek;
            if (c >= 0x530 && c <= 0x58F) return Script.Armenian;
            if (c >= 0x590 && c <= 0x5FF) return Script.Hebrew;
            if ((c >= 0x600 && c <= 0x6FF) || (c >= 0x750 && c <= 0x77F)) return Script.Arabic;
            if (c >= 0xE00 && c <= 0xE7F) return Script.Thai;
            if (c >= 0x3040 && c <= 0x309F) return Script.Hiragana;
            if (c >= 0x30A0 && c <= 0x30FF) return Script.Katakana;
            if ((c >= 0x3400 && c <= 0x4DBF) || (c >= 0x4E00 && c <= 0x9FFF) ||
                (c >= 0x20000 && c <= 0x2A6DF)) return Script.Han;
            if ((c >= 0x1100 && c <= 0x11FF) || (c >= 0xAC00 && c <= 0xD7AF)) return Script.Hangul;

            return Script.Other;
        }

        // Japanese (Han+Hiragana+Katakana) and Korean (Han+Hangul) legitimately mix scripts
        private static bool IsAllowedCombination(HashSet<Script> set)
        {
            return set.IsSubsetOf(new[] { Script.Han, Script.Hiragana, Script.Katakana }) ||
                   set.IsSubsetOf(new[] { Script.Han, Script.Hangul });
        }

        private static string FindMixedScriptLabel(string[] decodedLabels)
        {
            foreach (string label in decodedLabels)
            {
                var set = new HashSet<Script>();
                foreach (int cp in CodePoints(label))
                {
                    Script? s = ScriptOf(cp);
                    if (s.HasValue) set.Add(s.Value);
                }

                if (set.Count > 1 && !IsAllowedCombination(set))
                    return "Label '" + label + "' mixes " + string.Join(" + ", set);
            }
            return null;
        }


        // ------------------------------------------------------------------
        // Damerau-Levenshtein (optimal string alignment) distance
        // ------------------------------------------------------------------
        private static int EditDistance(string a, string b)
        {
            var d = new int[a.Length + 1, b.Length + 1];
            for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
            for (int j = 0; j <= b.Length; j++) d[0, j] = j;

            for (int i = 1; i <= a.Length; i++)
            {
                for (int j = 1; j <= b.Length; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);

                    if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                        d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
                }
            }
            return d[a.Length, b.Length];
        }
    }
}