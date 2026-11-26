using System;
using System.Collections.Generic;
using System.Linq;

namespace Project_check_URL.View
{
    // Формирует содержимое деталей (строки "метка: значение") для каждого пункта проверки.
    // HomeView вызывает эти методы и присваивает результат CheckItem.Details; DetailView только отображает.
    internal static class CheckDetails
    {
        private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

        // ================================================================
        // Общее
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
        // 1) Offline: анализ ссылки и домена
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

        // Punycode / Смешанные системы письма / Имитация бренда
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

        // Перечисляет не-ASCII символы с кодами Unicode, чтобы точно видеть подозрительные символы
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
                if (cp >= 0xD800 && cp <= 0xDFFF) continue;     // одиночный суррогат
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

            // остальные типы: timeout, failure, type-unsupported...
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
        // 2B) VirusTotal подробно, данные из VT_response.cs (VtReport / VtVerdict)
        //
        // Разделение ответственности, чтобы не дублировать содержимое:
        //  - Общий вывод (Level, Finding, Assessment) присваивается HomeView в CheckItem;
        //    DetailView показывает Assessment в блоке ASSESSMENT карточки, поэтому Details НЕ дублирует его.
        //  - Blacklist  : какие движки отметили и что означает эта метка.
        //  - Reputation : какие движки отнесли к harmless / undetected, охват.
        // ================================================================

        private static List<DetailLine> VtHeader(VtReport r)
        {
            var d = new List<DetailLine>();

            d.Add(new DetailLine("Analysis ID", r.AnalysisId));
            d.Add(new DetailLine("Status", r.Status));

            if (r.ScanDateUtc.HasValue)
                d.Add(new DetailLine("Scan date", Utc(r.ScanDateUtc.Value)));

            if (!string.IsNullOrEmpty(r.Url))
                d.Add(new DetailLine("URL analysed", r.Url));

            d.Add(new DetailLine("Engine verdicts",
                r.Malicious + " malicious  ·  " +
                r.Suspicious + " suspicious  ·  " +
                r.Harmless + " harmless  ·  " +
                r.Undetected + " undetected  ·  " +
                r.Timeout + " timeout"));

            d.Add(new DetailLine("Engines responded",
                r.Responding + " of " + r.TotalEngines));

            d.Add(new DetailLine("VirusTotal page",
                r.VtPageUrl ?? "Not available"));

            return d;
        }

        // BLACKLIST: движки, отметившие malicious / suspicious, со значением метки
        public static List<DetailLine> ForBlacklist(VtReport r, VtVerdict verdict)
        {
            List<DetailLine> d = VtHeader(r);

            if (verdict != null)
                d.Add(new DetailLine("Confidence", verdict.Confidence));

            int listed = 0;
            foreach (string category in new[] { "malicious", "suspicious" })
            {
                List<EngineVerdict> engines = r.Flagged(category);
                if (engines.Count == 0) continue;

                listed += engines.Count;
                d.Add(Heading("Flagged as " + category + " (" + engines.Count + ")"));

                foreach (EngineVerdict e in engines)
                {
                    string label = string.IsNullOrWhiteSpace(e.Result) ? category : e.Result;
                    d.Add(new DetailLine(e.Engine, label + "  -  " + VtVerdictBuilder.Meaning(e)));
                }
            }

            if (listed == 0)
            {
                int flagged = r.Malicious + r.Suspicious;
                d.Add(new DetailLine("Flagged by", flagged == 0
                    ? "No engine flagged this URL"
                    : "The response did not list which engines flagged it (" + flagged + " in the summary)"));
            }

            return d;
        }

        // REPUTATION: движки harmless / undetected / прочие (timeout...)
        public static List<DetailLine> ForReputation(VtReport r)
        {
            List<DetailLine> d = VtHeader(r);

            if (r.Engines.Count == 0)
            {
                d.Add(new DetailLine("Engines", "The response did not include per-engine results."));
                return d;
            }

            AddEngineNames(d, r, "harmless", "Harmless");
            AddEngineNames(d, r, "undetected", "Undetected");

            List<EngineVerdict> other = r.Engines
                .Where(e => !IsOneOf(e.Category, "malicious", "suspicious", "harmless", "undetected"))
                .ToList();
            if (other.Count > 0)
            {
                d.Add(Heading("Other (" + other.Count + ")"));
                foreach (EngineVerdict e in other)
                    d.Add(new DetailLine(e.Engine, e.Category ?? "Unknown"));
            }

            return d;
        }

        private static bool IsOneOf(string value, params string[] options)
        {
            return options.Any(o => string.Equals(value, o, StringComparison.OrdinalIgnoreCase));
        }

        private static void AddEngineNames(List<DetailLine> d, VtReport r, string category, string title)
        {
            List<string> names = r.Engines
                .Where(e => string.Equals(e.Category, category, StringComparison.OrdinalIgnoreCase))
                .Select(e => e.Engine)
                .ToList();

            if (names.Count == 0) return;

            d.Add(Heading(title + " (" + names.Count + ")"));
            d.Add(new DetailLine("Engines", string.Join(", ", names)));
        }

        // ================================================================
        // 3) HTML check: ответ сервера
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

        private static readonly HashSet<string> ExecutableExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".msi", ".com", ".scr", ".bat", ".cmd", ".ps1",
                ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".apk",
                ".dmg", ".pkg", ".sh", ".app", ".dll", ".sys", ".reg"
            };

        // Берёт имя файла из конечного URL; если его нет — из исходного URL.
        private static string UrlFileName(HttpProbeResult p)
        {
            if (p == null)
                return null;

            string source = !string.IsNullOrWhiteSpace(p.FinalUrl)
                ? p.FinalUrl
                : p.Url;

            Uri uri;
            if (!Uri.TryCreate(source, UriKind.Absolute, out uri))
                return null;

            string path;
            try
            {
                path = Uri.UnescapeDataString(uri.AbsolutePath);
            }
            catch
            {
                path = uri.AbsolutePath;
            }

            return System.IO.Path.GetFileName(path);
        }

        // Читает filename / filename* из Content-Disposition.
        private static string DispositionFileName(HttpProbeResult p)
        {
            if (p == null || p.Headers == null)
                return null;

            string value;
            if (!p.Headers.TryGetValue("Content-Disposition", out value)
                || string.IsNullOrWhiteSpace(value))
                return null;

            foreach (string part in value.Split(';'))
            {
                string item = part.Trim();

                if (item.StartsWith("filename*=", StringComparison.OrdinalIgnoreCase))
                {
                    string encoded = item.Substring(10).Trim().Trim('"');

                    // RFC 5987: charset'language'percent-encoded-value
                    int firstQuote = encoded.IndexOf('\'');
                    int secondQuote = firstQuote >= 0
                        ? encoded.IndexOf('\'', firstQuote + 1)
                        : -1;

                    if (secondQuote >= 0)
                        encoded = encoded.Substring(secondQuote + 1);

                    try
                    {
                        return Uri.UnescapeDataString(encoded);
                    }
                    catch
                    {
                        return encoded;
                    }
                }

                if (item.StartsWith("filename=", StringComparison.OrdinalIgnoreCase))
                    return item.Substring(9).Trim().Trim('"');
            }

            return null;
        }

        // Проверяет все расширения, чтобы поймать и маскировку вроде setup.exe.pdf.
        private static bool HasExecutableExtension(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            string name = fileName.Trim().Trim('"');

            // Убираем путь, если сервер прислал его вместе с filename.
            name = name.Replace('\\', '/');
            int slash = name.LastIndexOf('/');
            if (slash >= 0)
                name = name.Substring(slash + 1);

            string[] parts = name.Split('.');
            for (int i = 1; i < parts.Length; i++)
            {
                string extension = "." + parts[i].Trim();
                if (ExecutableExtensions.Contains(extension))
                    return true;
            }

            return false;
        }

        // Оценивает тип содержимого, возвращаемого сервером.
        public static string ContentTypeLevel(HttpProbeResult p)
        {
            if (p == null)
                return "Warning";

            string type = (p.ContentType ?? string.Empty).Trim();

            // Content-Type может содержать параметры, например "; charset=utf-8".
            int parameterIndex = type.IndexOf(';');
            string mediaType = parameterIndex >= 0
                ? type.Substring(0, parameterIndex).Trim()
                : type;

            string urlName = UrlFileName(p);
            string downloadName = DispositionFileName(p);

            if (ExecutableTypes.Contains(mediaType)
                || HasExecutableExtension(urlName)
                || HasExecutableExtension(downloadName))
            {
                return "Danger";
            }

            string disposition = null;
            if (p.Headers != null)
                p.Headers.TryGetValue("Content-Disposition", out disposition);

            if (!string.IsNullOrWhiteSpace(disposition)
                && disposition.TrimStart().StartsWith(
                    "attachment", StringComparison.OrdinalIgnoreCase))
            {
                return "Warning";
            }

            if (mediaType.Length == 0)
                return "Warning";

            string t = mediaType.ToLowerInvariant();

            if (t.StartsWith("text/")
                || t.StartsWith("image/")
                || t == "application/xhtml+xml"
                || t == "application/json")
            {
                return "Safe";
            }

            return "Warning";
        }

        // Оценивает всю цепочку редиректов, а не только финальный HTTP-статус.
        public static string RedirectsLevel(HttpProbeResult p)
        {
            if (p == null || !string.IsNullOrEmpty(p.Error)
                || p.StatusCode < 200 || p.StatusCode >= 400)
            {
                return "Warning";
            }

            if (p.RedirectChain == null)
                return "Warning";

            for (int i = 1; i < p.RedirectChain.Count; i++)
            {
                Uri previous;
                Uri next;

                if (!Uri.TryCreate(
                        p.RedirectChain[i - 1],
                        UriKind.Absolute,
                        out previous)
                    || !Uri.TryCreate(
                        p.RedirectChain[i],
                        UriKind.Absolute,
                        out next))
                {
                    return "Warning";
                }

                // Понижение HTTPS до HTTP снижает защиту соединения.
                if (previous.Scheme == Uri.UriSchemeHttps
                    && next.Scheme == Uri.UriSchemeHttp)
                {
                    return "Warning";
                }

                // Переход на другое имя хоста требует внимания пользователя.
                if (!string.Equals(
                    previous.IdnHost,
                    next.IdnHost,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return "Warning";
                }
            }

            // Только 2xx считается успешным финальным ответом.
            return p.StatusCode >= 200 && p.StatusCode < 300
                ? "Safe"
                : "Warning";
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
            d.Add(new DetailLine("Note",
                "A change of host or HTTPS-to-HTTP downgrade is treated as a warning."));
            d.Add(new DetailLine("Redirect security assessment",
                RedirectsLevel(p)));
            d.Add(new DetailLine("Redirect assessment note",
                "A hostname change or HTTPS-to-HTTP downgrade is treated as a warning."));
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

            d.Add(new DetailLine("Content-Type",
                p.RawContentType ?? "Not provided by the server"));

            d.Add(new DetailLine("Media type",
                p.ContentType ?? "-"));

            d.Add(new DetailLine("Charset",
                CharsetOf(p.RawContentType) ?? "Not declared"));

            var shown = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Content-Type"
    };

            string[] key =
            {
        "Content-Length",
        "Content-Disposition",
        "X-Content-Type-Options",
        "Server"
    };

            foreach (string name in key)
            {
                string value;
                bool has = p.Headers.TryGetValue(name, out value);

                d.Add(new DetailLine(name, has ? value : "Not set"));
                shown.Add(name);
            }

            // Разбор имени файла из URL и Content-Disposition
            string urlName = UrlFileName(p);
            string dispositionName = DispositionFileName(p);

            d.Add(new DetailLine("URL file name",
                urlName ?? "Not available"));

            d.Add(new DetailLine("Content-Disposition file name",
                dispositionName ?? "Not provided"));

            d.Add(new DetailLine("Executable extension detected",
                HasExecutableExtension(urlName)
                || HasExecutableExtension(dispositionName)
                    ? "Yes"
                    : "No"));

            // Информация об ответе
            d.Add(new DetailLine("Page body",
                "Not downloaded. Only the response headers are read."));

            d.Add(new DetailLine("Final URL", p.FinalUrl));

            if (p.Error != null)
                d.Add(new DetailLine("Error", p.Error));

            // Остальные HTTP-заголовки
            List<KeyValuePair<string, string>> rest =
                p.Headers
                    .Where(h => !shown.Contains(h.Key))
                    .OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase)
                    .ToList();

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