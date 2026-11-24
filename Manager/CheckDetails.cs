using System;
using System.Collections.Generic;
using System.Linq;

namespace Project_check_URL.View
{
    // Dựng nội dung chi tiết (các dòng "nhãn: giá trị") cho từng mục kiểm tra.
    // HomeView gọi các hàm này rồi gán vào CheckItem.Details; DetailView chỉ việc hiển thị.
    internal static class CheckDetails
    {
        private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

        // ================================================================
        // Dùng chung
        // ================================================================

        private static DetailLine Heading(string text)
        {
            return new DetailLine(text, null);
        }

        private static string Utc(DateTime t)
        {
            return t.ToString(TimeFormat) + " UTC";
        }

        public static List<DetailLine> Pending(string text)
        {
            return new List<DetailLine> { new DetailLine("Status", text) };
        }

        public static List<DetailLine> ForError(string source, Exception ex)
        {
            var d = new List<DetailLine>();
            d.Add(new DetailLine("Status", source + " result is not available"));
            d.Add(new DetailLine("Reason", ex.Message));
            d.Add(new DetailLine("Error type", ex.GetType().Name));

            var timeout = ex as ScanTimeoutException;
            if (timeout != null)
                d.Add(new DetailLine("Analysis ID", timeout.AnalysisId));

            var quota = ex as VirusTotalQuotaException;
            if (quota != null && quota.RetryAfter.HasValue)
                d.Add(new DetailLine("Retry after", (int)quota.RetryAfter.Value.TotalSeconds + " seconds"));

            return d;
        }

        // ================================================================
        // 1) Offline: phân tích đường link và tên miền
        // ================================================================

        public static List<DetailLine> ForProtocol(Uri uri)
        {
            var d = new List<DetailLine>();
            d.Add(new DetailLine("Scheme", uri.Scheme));
            d.Add(new DetailLine("Encrypted",
                uri.Scheme == Uri.UriSchemeHttps
                    ? "Yes, traffic is protected by TLS"
                    : "No, traffic can be read or changed on the way"));
            d.Add(new DetailLine("Port",
                uri.Port + (uri.IsDefaultPort ? " (default for " + uri.Scheme + ")" : " (custom port)")));
            d.Add(new DetailLine("User info",
                string.IsNullOrEmpty(uri.UserInfo)
                    ? "None"
                    : uri.UserInfo + "  (text before @ can hide the real host)"));
            d.Add(new DetailLine("Path", uri.AbsolutePath));
            d.Add(new DetailLine("Query", string.IsNullOrEmpty(uri.Query) ? "None" : uri.Query));
            d.Add(new DetailLine("Fragment", string.IsNullOrEmpty(uri.Fragment) ? "None" : uri.Fragment));
            return d;
        }

        public static List<DetailLine> ForDomain(Uri uri)
        {
            var d = new List<DetailLine>();
            d.Add(new DetailLine("Host", uri.Host));
            d.Add(new DetailLine("Host type", uri.HostNameType.ToString()));

            if (uri.HostNameType != UriHostNameType.Dns)
            {
                d.Add(new DetailLine("Note", "The host is an IP address, so the domain-name checks do not apply."));
                return d;
            }

            string host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
            string[] labels = host.Split('.');
            bool broken;
            string decoded = Offline_check.ToUnicodeSafe(labels, out broken);
            string[] decodedLabels = decoded.Split('.');

            d.Add(new DetailLine("ASCII form", host));
            d.Add(new DetailLine("Unicode form", decoded));
            d.Add(new DetailLine("Registrable domain", Offline_check.GetRegistrableDomain(decodedLabels)));
            d.Add(new DetailLine("Labels", labels.Length.ToString()));
            return d;
        }

        // Punycode / Mixed writing systems / Brand impersonation
        public static List<DetailLine> ForHomograph(Uri uri, CheckFinding f)
        {
            var d = new List<DetailLine>();

            if (uri.HostNameType != UriHostNameType.Dns)
            {
                d.Add(new DetailLine("Note", "The host is an IP address, so this check does not apply."));
                return d;
            }

            string host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
            string[] labels = host.Split('.');
            bool broken;
            string decoded = Offline_check.ToUnicodeSafe(labels, out broken);
            string[] decodedLabels = decoded.Split('.');

            switch (f.Criterion)
            {
                case "Punycode (IDN)":
                    d.Add(new DetailLine("ASCII form", host));
                    d.Add(new DetailLine("Decoded form", decoded));
                    for (int i = 0; i < labels.Length; i++)
                    {
                        bool puny = labels[i].StartsWith("xn--", StringComparison.Ordinal);
                        string shown = i < decodedLabels.Length ? decodedLabels[i] : labels[i];
                        d.Add(new DetailLine("Label " + (i + 1),
                            puny ? labels[i] + "  ->  " + shown : labels[i] + "  (plain ASCII)"));
                    }
                    if (broken)
                        d.Add(new DetailLine("Decoding", "At least one xn-- label could not be decoded"));
                    break;

                case "Mixed writing systems":
                    d.Add(new DetailLine("Decoded form", decoded));
                    d.Add(new DetailLine("Non-ASCII characters", NonAscii(decoded)));
                    d.Add(new DetailLine("Rule", "One label must not mix scripts, for example Latin with Cyrillic."));
                    break;

                case "Brand impersonation":
                    string registrable = Offline_check.GetRegistrableDomain(decodedLabels);
                    d.Add(new DetailLine("Registrable domain", registrable));
                    d.Add(new DetailLine("Confusables table",
                        Offline_check.IsConfusablesLoaded ? "Loaded" : "Not loaded, the check was skipped"));
                    d.Add(new DetailLine("Known brands compared", Offline_check.Brands.Length.ToString()));
                    if (Offline_check.IsConfusablesLoaded)
                    {
                        try
                        {
                            d.Add(new DetailLine("Skeleton", Offline_check.LooseSkeleton(registrable)));
                        }
                        catch (ArgumentException)
                        {
                            d.Add(new DetailLine("Skeleton", "Cannot be computed for this domain"));
                        }
                    }
                    d.Add(new DetailLine("Rule",
                        "Official brand domain = Safe. Same skeleton as a brand = Danger. One character away = Warning."));
                    break;

                default:
                    d.Add(new DetailLine("Decoded form", decoded));
                    break;
            }

            return d;
        }

        // Liệt kê các ký tự ngoài ASCII kèm mã Unicode, để thấy chính xác ký tự nào đáng ngờ
        private static string NonAscii(string text)
        {
            var seen = new HashSet<int>();
            var list = new List<string>();

            for (int i = 0; i < text.Length; i++)
            {
                int cp;
                if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                {
                    cp = char.ConvertToUtf32(text[i], text[i + 1]);
                    i++;
                }
                else
                {
                    cp = text[i];
                }

                if (cp <= 127) continue;
                if (cp >= 0xD800 && cp <= 0xDFFF) continue;     // surrogate lẻ
                if (seen.Add(cp))
                    list.Add(char.ConvertFromUtf32(cp) + " (U+" + cp.ToString("X4") + ")");
            }

            return list.Count == 0 ? "None" : string.Join(", ", list);
        }

        // ================================================================
        // 2) VirusTotal
        // ================================================================

        private static List<DetailLine> VtHeader(ScanResult r)
        {
            var d = new List<DetailLine>();
            d.Add(new DetailLine("Analysis ID", r.AnalysisId));
            d.Add(new DetailLine("Status", r.Status));
            if (r.ScanDate.HasValue)
                d.Add(new DetailLine("Scan date", Utc(r.ScanDate.Value)));
            if (!string.IsNullOrEmpty(r.ScannedUrl))
                d.Add(new DetailLine("URL analysed", r.ScannedUrl));

            string counts = r.Malicious + " malicious  ·  " + r.Suspicious + " suspicious  ·  "
                          + r.Harmless + " harmless  ·  " + r.Undetected + " undetected";
            if (r.Timeout > 0) counts += "  ·  " + r.Timeout + " timeout";
            d.Add(new DetailLine("Engine verdicts", counts));
            d.Add(new DetailLine("VirusTotal page", r.ReportLink ?? "Not available"));
            return d;
        }

        public static List<DetailLine> ForBlacklist(ScanResult r)
        {
            List<DetailLine> d = VtHeader(r);

            if (r.Engines.Count == 0)
            {
                d.Add(new DetailLine("Engines", "The response did not include per-engine results."));
                return d;
            }

            int flagged = 0;
            foreach (string category in new[] { "malicious", "suspicious" })
            {
                List<EngineResult> group = r.Engines.Where(e => e.Category == category).ToList();
                if (group.Count == 0) continue;

                flagged += group.Count;
                d.Add(Heading("Flagged as " + category + " (" + group.Count + ")"));
                foreach (EngineResult e in group)
                    d.Add(new DetailLine(e.Engine, string.IsNullOrEmpty(e.Result) ? category : e.Result));
            }

            if (flagged == 0)
                d.Add(new DetailLine("Flagged by", "No engine flagged this URL"));

            return d;
        }

        public static List<DetailLine> ForReputation(ScanResult r)
        {
            List<DetailLine> d = VtHeader(r);

            if (r.Engines.Count == 0)
            {
                d.Add(new DetailLine("Engines", "The response did not include per-engine results."));
                return d;
            }

            AddEngineNames(d, r, "harmless", "Harmless");
            AddEngineNames(d, r, "undetected", "Undetected");

            // các loại còn lại: timeout, failure, type-unsupported...
            List<EngineResult> other = r.Engines
                .Where(e => e.Category != "malicious" && e.Category != "suspicious"
                         && e.Category != "harmless" && e.Category != "undetected")
                .ToList();
            if (other.Count > 0)
            {
                d.Add(Heading("Other (" + other.Count + ")"));
                foreach (EngineResult e in other)
                    d.Add(new DetailLine(e.Engine, e.Category));
            }

            return d;
        }

        private static void AddEngineNames(List<DetailLine> d, ScanResult r, string category, string title)
        {
            List<string> names = r.Engines
                .Where(e => e.Category == category)
                .Select(e => e.Engine)
                .ToList();
            if (names.Count == 0) return;

            d.Add(Heading(title + " (" + names.Count + ")"));
            d.Add(new DetailLine("Engines", string.Join(", ", names)));
        }

        // ================================================================
        // 3) HTML check: phản hồi của máy chủ
        // ================================================================

        private static readonly HashSet<string> ExecutableTypes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
                "application/vnd.microsoft.portable-executable", "application/x-msi",
                "application/x-executable", "application/x-sh", "application/x-bat", "application/hta",
                "application/java-archive", "application/x-java-archive",
                "application/vnd.android.package-archive", "application/x-apple-diskimage"
            };

        // Safe: trang web / văn bản / ảnh. Warning: thiếu header, tải về, hoặc loại tệp khác.
        // Danger: tệp thực thi hoặc trình cài đặt.
        public static string ContentTypeLevel(HttpProbeResult p)
        {
            string type = (p.ContentType ?? string.Empty).Trim();
            if (type.Length == 0) return "Warning";
            if (ExecutableTypes.Contains(type)) return "Danger";

            string disposition;
            if (p.Headers.TryGetValue("Content-Disposition", out disposition)
                && disposition.TrimStart().StartsWith("attachment", StringComparison.OrdinalIgnoreCase))
                return "Warning";

            string t = type.ToLowerInvariant();
            if (t.StartsWith("text/") || t.StartsWith("image/")
                || t == "application/xhtml+xml" || t == "application/json")
                return "Safe";

            return "Warning";
        }

        public static List<DetailLine> ForRedirects(HttpProbeResult p)
        {
            var d = new List<DetailLine>();
            d.Add(new DetailLine("Requested URL", p.Url));
            d.Add(new DetailLine("Final URL", p.FinalUrl));
            d.Add(new DetailLine("Final status", p.StatusCode > 0
                ? p.StatusCode + (string.IsNullOrEmpty(p.ReasonPhrase) ? "" : " " + p.ReasonPhrase)
                : "No response"));
            d.Add(new DetailLine("Redirects followed",
                Math.Max(0, p.RedirectChain.Count - 1) + "  (limit 5)"));
            if (p.Error != null)
                d.Add(new DetailLine("Error", p.Error));
            d.Add(new DetailLine("Checked at", Utc(p.ProbedAt)));

            for (int i = 0; i < p.RedirectChain.Count; i++)
            {
                d.Add(Heading("Step " + (i + 1)));
                d.Add(new DetailLine("URL", p.RedirectChain[i]));

                if (i >= p.Hops.Count)
                {
                    d.Add(new DetailLine("Response", "None" + (p.Error != null ? " (" + p.Error + ")" : "")));
                    continue;
                }

                HttpHop hop = p.Hops[i];
                d.Add(new DetailLine("Resolved IP", hop.Ips));
                d.Add(new DetailLine("Response",
                    hop.StatusCode + (string.IsNullOrEmpty(hop.ReasonPhrase) ? "" : " " + hop.ReasonPhrase)));
                if (!string.IsNullOrEmpty(hop.Location))
                    d.Add(new DetailLine("Location", hop.Location));

                if (hop.TlsProtocol != null)
                {
                    d.Add(new DetailLine("TLS protocol", hop.TlsProtocol));
                    if (hop.CertSubject != null) d.Add(new DetailLine("Certificate subject", hop.CertSubject));
                    if (hop.CertIssuer != null) d.Add(new DetailLine("Certificate issuer", hop.CertIssuer));
                    if (hop.CertNotBefore.HasValue && hop.CertNotAfter.HasValue)
                        d.Add(new DetailLine("Certificate valid",
                            Utc(hop.CertNotBefore.Value) + "  to  " + Utc(hop.CertNotAfter.Value)));
                }
            }

            return d;
        }

        public static List<DetailLine> ForContentType(HttpProbeResult p)
        {
            var d = new List<DetailLine>();
            d.Add(new DetailLine("Content-Type", p.RawContentType ?? "Not provided by the server"));
            d.Add(new DetailLine("Media type", p.ContentType ?? "-"));
            d.Add(new DetailLine("Charset", CharsetOf(p.RawContentType) ?? "Not declared"));

            var shown = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Content-Type" };
            string[] key = { "Content-Length", "Content-Disposition", "X-Content-Type-Options", "Server" };
            foreach (string name in key)
            {
                string value;
                bool has = p.Headers.TryGetValue(name, out value);
                d.Add(new DetailLine(name, has ? value : "Not set"));
                shown.Add(name);
            }

            d.Add(new DetailLine("Page body", "Not downloaded. Only the response headers are read."));
            d.Add(new DetailLine("Final URL", p.FinalUrl));
            if (p.Error != null)
                d.Add(new DetailLine("Error", p.Error));

            List<KeyValuePair<string, string>> rest =
                p.Headers.Where(h => !shown.Contains(h.Key)).OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase).ToList();

            d.Add(Heading("Other response headers (" + rest.Count + ")"));
            if (rest.Count == 0)
                d.Add(new DetailLine("Headers", "None"));
            foreach (KeyValuePair<string, string> h in rest)
                d.Add(new DetailLine(h.Key, h.Value));

            return d;
        }

        private static string CharsetOf(string rawContentType)
        {
            if (string.IsNullOrEmpty(rawContentType)) return null;

            int i = rawContentType.IndexOf("charset=", StringComparison.OrdinalIgnoreCase);
            if (i < 0) return null;

            string v = rawContentType.Substring(i + "charset=".Length);
            int semi = v.IndexOf(';');
            if (semi >= 0) v = v.Substring(0, semi);
            v = v.Trim().Trim('"');
            return v.Length == 0 ? null : v;
        }
    }
}
