using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Project_check_URL.View;

namespace Project_check_URL
{
    // Kết quả kiểm tra tĩnh (homograph / thương hiệu / IP) của một host nằm trong chuỗi redirect
    internal class HostStaticCheck
    {
        public string Host { get; set; }
        public List<CheckFinding> Findings { get; set; }
        public string Level { get; set; }
    }

    // ------------------------------------------------------------------
    // Đánh giá thẻ "Redirects" từ kết quả thăm dò HTTP.
    // Trước đây thẻ này chỉ xét mã trạng thái cuối nên gần như luôn "Safe";
    // nay xét cả chuỗi chuyển hướng: đổi site, hạ cấp HTTPS, nhiều bước, TLS cũ,
    // header Refresh, và chạy lại kiểm tra tĩnh cho từng host đích.
    // ------------------------------------------------------------------
    internal class RedirectAnalysis
    {
        public string Level { get; private set; }
        public string Finding { get; private set; }
        public string Assessment { get; private set; }

        public int Redirects { get; private set; }
        public bool CrossSite { get; private set; }
        public bool Downgrade { get; private set; }
        public bool StartsOnShortener { get; private set; }
        public string RefreshTarget { get; private set; }
        public bool RefreshCrossSite { get; private set; }
        public List<string> OutdatedTls { get; private set; }
        public List<string> Sites { get; private set; }               // các site (tên miền đăng ký được) đã đi qua, theo thứ tự
        public List<HostStaticCheck> HostChecks { get; private set; } // kiểm tra tĩnh cho host khác host ban đầu
        public List<string> Reasons { get; private set; }

        private static readonly Regex RxRefreshUrl =
            new Regex(@"url\s*=\s*['""]?\s*([^'"";,\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

        private static readonly string[] OutdatedProtocols = { "Ssl2", "Ssl3", "Tls", "Tls11" };

        private RedirectAnalysis()
        {
            Level = "Safe";
            OutdatedTls = new List<string>();
            Sites = new List<string>();
            HostChecks = new List<HostStaticCheck>();
            Reasons = new List<string>();
        }

        private void Raise(string level, string reason)
        {
            if (level == "Danger" || (level == "Warning" && Level == "Safe")) Level = level;
            if (!string.IsNullOrEmpty(reason)) Reasons.Add(reason);
        }

        public static RedirectAnalysis Analyze(HttpProbeResult p)
        {
            var a = new RedirectAnalysis();

            // ---- chuỗi URL ----
            var uris = new List<Uri>();
            foreach (string u in p.RedirectChain)
            {
                Uri parsed;
                if (Uri.TryCreate(u, UriKind.Absolute, out parsed)) uris.Add(parsed);
            }
            a.Redirects = Math.Max(0, p.RedirectChain.Count - 1);

            foreach (Uri u in uris)
            {
                string site = DomainUtil.Registrable(u.IdnHost);
                if (site != null && (a.Sites.Count == 0 || !string.Equals(a.Sites[a.Sites.Count - 1], site, StringComparison.OrdinalIgnoreCase)))
                    a.Sites.Add(site);
            }
            a.CrossSite = a.Sites.Count > 1;

            for (int i = 1; i < uris.Count; i++)
                if (uris[i - 1].Scheme == Uri.UriSchemeHttps && uris[i].Scheme == Uri.UriSchemeHttp)
                    a.Downgrade = true;

            a.StartsOnShortener = uris.Count > 0 && DomainUtil.IsShortener(uris[0].IdnHost);

            // ---- header Refresh của bước cuối (một dạng chuyển hướng mà probe KHÔNG đi theo) ----
            string refresh;
            if (p.Headers.TryGetValue("Refresh", out refresh) && uris.Count > 0)
            {
                try
                {
                    Match m = RxRefreshUrl.Match(refresh);
                    if (m.Success)
                    {
                        Uri target;
                        Uri last = uris[uris.Count - 1];
                        if (Uri.TryCreate(last, m.Groups[1].Value, out target) &&
                            (target.Scheme == Uri.UriSchemeHttp || target.Scheme == Uri.UriSchemeHttps))
                        {
                            a.RefreshTarget = target.AbsoluteUri;
                            a.RefreshCrossSite = !DomainUtil.SameSite(target.IdnHost, last.IdnHost);
                        }
                    }
                }
                catch (RegexMatchTimeoutException) { }
            }

            // ---- TLS cũ ----
            foreach (HttpHop hop in p.Hops)
                if (hop.TlsProtocol != null && OutdatedProtocols.Contains(hop.TlsProtocol) && !a.OutdatedTls.Contains(hop.TlsProtocol))
                    a.OutdatedTls.Add(hop.TlsProtocol);

            // ---- kiểm tra tĩnh các host đích (khác host ban đầu) ----
            if (uris.Count > 1)
            {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { uris[0].IdnHost };
                for (int i = 1; i < uris.Count; i++)
                {
                    if (!seen.Add(uris[i].IdnHost)) continue;

                    List<CheckFinding> findings;
                    try { findings = Offline_check.CheckHomograph(uris[i]); }
                    catch (Exception) { continue; }

                    // Bỏ cảnh báo "chưa nạp confusables.txt": nó không nói gì về host này
                    findings = findings.Where(f => f.Finding == null || !f.Finding.StartsWith("confusables.txt not loaded", StringComparison.Ordinal)).ToList();

                    string level = findings.Any(f => f.Level == "Danger") ? "Danger" :
                                   findings.Any(f => f.Level == "Warning") ? "Warning" : "Safe";
                    a.HostChecks.Add(new HostStaticCheck { Host = uris[i].IdnHost, Findings = findings, Level = level });
                }
            }

            // ---- tổng hợp mức độ ----
            if (p.Error != null)
            {
                a.Raise("Warning", "The server could not be checked (" + p.Error + ").");
            }
            else
            {
                if (p.StatusCode >= 300 && p.StatusCode < 400)
                    a.Raise("Warning", "The server answered with a redirect (" + p.StatusCode + ") but gave no usable destination.");
                else if (p.StatusCode >= 400)
                    a.Raise("Warning", "The server answered with an error (" + p.StatusCode + "). The page may have been removed, or it may block automated checks.");
            }

            if (a.CrossSite)
                a.Raise("Warning", "The link redirects to a different site (" + string.Join(" -> ", a.Sites) + ").");
            if (a.Downgrade)
                a.Raise("Warning", "A redirect moves from HTTPS to plain HTTP, so the connection is no longer protected.");
            if (a.Redirects >= 3)
                a.Raise("Warning", "The link passes through " + a.Redirects + " redirects before the final page.");
            if (a.RefreshCrossSite)
                a.Raise("Warning", "The final page sends the visitor to another site through a Refresh header (" + a.RefreshTarget + ").");
            if (a.OutdatedTls.Count > 0)
                a.Raise("Warning", "A server uses an outdated TLS version (" + string.Join(", ", a.OutdatedTls) + ").");

            foreach (HostStaticCheck h in a.HostChecks.Where(x => x.Level != "Safe"))
            {
                CheckFinding worst = h.Findings.FirstOrDefault(f => f.Level == h.Level);
                a.Raise(h.Level, "The redirect target " + h.Host + " is suspicious" +
                                 (worst != null ? " (" + worst.Criterion + ": " + worst.Finding + ")" : "") + ".");
            }

            // ---- chữ hiện ở Home và hộp Assessment ----
            if (p.Error != null)
            {
                a.Finding = p.Error;
            }
            else
            {
                a.Finding = p.StatusCode.ToString();
                if (a.Redirects > 0) a.Finding += "  ·  " + a.Redirects + (a.Redirects == 1 ? " redirect" : " redirects");
                if (a.CrossSite) a.Finding += "  ·  other site";
            }

            if (a.Reasons.Count > 0)
            {
                string joined = string.Join(" ", a.Reasons);
                a.Assessment = a.Level == "Danger"
                    ? "High risk. " + joined + " Do not open this link or enter any information."
                    : joined + " Check that the final address is what you expect before you continue.";
            }
            return a;
        }
    }
}
