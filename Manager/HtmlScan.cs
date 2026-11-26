using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Project_check_URL
{
    internal class HtmlForm
    {
        public string Action { get; set; }     // địa chỉ tuyệt đối (hoặc "(same page)")
        public string Method { get; set; }
        public bool HasPassword { get; set; }
        public bool External { get; set; }     // gửi sang site khác
        public bool Insecure { get; set; }     // gửi qua HTTP thường
    }

    internal class HtmlFrame
    {
        public string Src { get; set; }
        public bool Hidden { get; set; }
        public bool External { get; set; }
    }

    internal class HtmlScanResult
    {
        public string Title { get; set; }
        public string Charset { get; set; }
        public int Length { get; set; }
        public bool Truncated { get; set; }
        public string MetaRefreshTarget { get; set; }
        public string MetaRefreshDelay { get; set; }
        public bool MetaRefreshExternal { get; set; }
        public int PasswordFields { get; set; }
        public bool JsRedirectHint { get; set; }
        public string Note { get; set; }
        public List<HtmlForm> Forms { get; private set; }
        public List<HtmlFrame> Frames { get; private set; }
        public List<string> ExternalScriptHosts { get; private set; }
        public List<string> Warnings { get; private set; }

        public string Level { get { return Warnings.Count > 0 ? "Warning" : "Safe"; } }

        public HtmlScanResult()
        {
            Forms = new List<HtmlForm>();
            Frames = new List<HtmlFrame>();
            ExternalScriptHosts = new List<string>();
            Warnings = new List<string>();
        }
    }

    // ------------------------------------------------------------------
    // Phân tích phần đầu của trang HTML như VĂN BẢN THUẦN: không chạy script,
    // không tải thêm tài nguyên nào. Mọi regex đều có timeout vì nội dung do
    // máy chủ (có thể độc hại) quyết định.
    // ------------------------------------------------------------------
    internal static class HtmlScan
    {
        private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(500);
        private const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant;

        private static readonly Regex RxScript = new Regex(@"<script\b([^>]*)>(.*?)</script\s*>", Opt, RxTimeout);
        private static readonly Regex RxStyle = new Regex(@"<style\b[^>]*>.*?</style\s*>", Opt, RxTimeout);
        private static readonly Regex RxComment = new Regex(@"<!--.*?-->", Opt, RxTimeout);
        private static readonly Regex RxTitle = new Regex(@"<title\b[^>]*>(.*?)</title\s*>", Opt, RxTimeout);
        private static readonly Regex RxTag = new Regex(@"<\s*(/?)\s*(form|input|iframe|frame|meta|base)\b([^>]*)>", Opt, RxTimeout);
        private static readonly Regex RxAttr = new Regex(@"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s""'>]+))", Opt, RxTimeout);
        private static readonly Regex RxCharsetMeta = new Regex(@"charset\s*=\s*[""']?\s*([A-Za-z0-9_\-]+)", Opt, RxTimeout);
        private static readonly Regex RxRefresh = new Regex(@"^\s*(\d+(?:\.\d+)?)\s*(?:[;,]\s*(?:url\s*=\s*)?['""]?\s*([^'"">]*))?", Opt, RxTimeout);
        private static readonly Regex RxJsRedirect = new Regex(@"(?:window|document|top|self|parent)\.location(?:\.href)?\s*=(?!=)|(?<![\w.])location(?:\.href)?\s*=(?!=)|location\.(?:replace|assign)\s*\(", Opt, RxTimeout);

        private const int MaxItems = 20;

        public static HtmlScanResult Analyze(byte[] body, string contentTypeHeader, Uri pageUri, bool truncated)
        {
            var r = new HtmlScanResult { Length = body == null ? 0 : body.Length, Truncated = truncated };
            if (body == null || body.Length == 0)
            {
                r.Note = "The page body is empty.";
                return r;
            }

            try
            {
                string html = Decode(body, contentTypeHeader, r);
                Scan(html, pageUri, r);
            }
            catch (RegexMatchTimeoutException)
            {
                r.Note = "The page is too complex to analyse safely, so only part of it was checked.";
            }
            return r;
        }

        // ---------------- giải mã ----------------

        private static string Decode(byte[] body, string contentTypeHeader, HtmlScanResult r)
        {
            string charset = null;
            if (!string.IsNullOrEmpty(contentTypeHeader))
            {
                Match m = RxCharsetMeta.Match(contentTypeHeader);
                if (m.Success) charset = m.Groups[1].Value;
            }
            if (charset == null)
            {
                string head = Encoding.ASCII.GetString(body, 0, Math.Min(body.Length, 2048));
                Match m = RxCharsetMeta.Match(head);
                if (m.Success) charset = m.Groups[1].Value;
            }

            Encoding enc = new UTF8Encoding(false, false);
            if (!string.IsNullOrEmpty(charset))
            {
                try { enc = Encoding.GetEncoding(charset); r.Charset = charset; }
                catch (ArgumentException) { r.Charset = charset + " (unknown, read as UTF-8)"; }
            }
            return enc.GetString(body);
        }

        // ---------------- quét ----------------

        private static void Scan(string html, Uri page, HtmlScanResult r)
        {
            // 1) script: lấy host script ngoài + dấu hiệu chuyển trang bằng JS, rồi bỏ ruột script
            foreach (Match m in RxScript.Matches(html))
            {
                string src = Attr(m.Groups[1].Value, "src");
                if (src != null)
                {
                    Uri abs = Resolve(page, src);
                    if (abs != null && IsWeb(abs) && !DomainUtil.SameSite(abs.IdnHost, page.IdnHost)
                        && !r.ExternalScriptHosts.Contains(abs.IdnHost) && r.ExternalScriptHosts.Count < 30)
                        r.ExternalScriptHosts.Add(abs.IdnHost);
                }
                else if (!r.JsRedirectHint && RxJsRedirect.IsMatch(m.Groups[2].Value))
                {
                    r.JsRedirectHint = true;
                }
            }
            string text = RxScript.Replace(html, " ");
            text = RxStyle.Replace(text, " ");
            text = RxComment.Replace(text, " ");

            // 2) tiêu đề
            Match t = RxTitle.Match(text);
            if (t.Success)
                r.Title = Clean(WebUtility.HtmlDecode(t.Groups[1].Value), 200);

            // 3) form / input / iframe / meta / base theo thứ tự xuất hiện
            HtmlForm current = null;
            Uri baseUri = page;
            foreach (Match m in RxTag.Matches(text))
            {
                bool closing = m.Groups[1].Value == "/";
                string name = m.Groups[2].Value.ToLowerInvariant();
                string attrs = m.Groups[3].Value;

                if (name == "form")
                {
                    if (closing) { current = null; continue; }
                    if (r.Forms.Count >= MaxItems) continue;
                    current = MakeForm(attrs, baseUri, page);
                    r.Forms.Add(current);
                }
                else if (closing)
                {
                    continue;
                }
                else if (name == "input")
                {
                    string type = (Attr(attrs, "type") ?? "").Trim().ToLowerInvariant();
                    if (type == "password")
                    {
                        r.PasswordFields++;
                        if (current != null) current.HasPassword = true;
                    }
                }
                else if (name == "iframe" || name == "frame")
                {
                    if (r.Frames.Count >= MaxItems) continue;
                    string src = Attr(attrs, "src");
                    Uri abs = src == null ? null : Resolve(baseUri, src);
                    if (abs == null || !IsWeb(abs)) continue;
                    r.Frames.Add(new HtmlFrame
                    {
                        Src = Clean(abs.AbsoluteUri, 300),
                        Hidden = IsHiddenFrame(attrs),
                        External = !DomainUtil.SameSite(abs.IdnHost, page.IdnHost)
                    });
                }
                else if (name == "base")
                {
                    string href = Attr(attrs, "href");
                    Uri abs = href == null ? null : Resolve(page, href);
                    if (abs != null && IsWeb(abs)) baseUri = abs;
                }
                else if (name == "meta" && r.MetaRefreshTarget == null)
                {
                    string equiv = Attr(attrs, "http-equiv");
                    if (equiv != null && equiv.Trim().Equals("refresh", StringComparison.OrdinalIgnoreCase))
                        ReadMetaRefresh(Attr(attrs, "content"), baseUri, page, r);
                }
            }

            BuildWarnings(page, r);
        }

        private static HtmlForm MakeForm(string attrs, Uri baseUri, Uri page)
        {
            var f = new HtmlForm { Method = (Attr(attrs, "method") ?? "GET").Trim().ToUpperInvariant() };
            string action = Attr(attrs, "action");

            if (string.IsNullOrWhiteSpace(action))
            {
                f.Action = "(same page)";
                f.Insecure = page.Scheme == Uri.UriSchemeHttp;
                return f;
            }

            Uri abs = Resolve(baseUri, action.Trim());
            if (abs == null || !IsWeb(abs))
            {
                f.Action = Clean(action.Trim(), 200);   // javascript:, mailto:, ...
                return f;
            }

            f.Action = Clean(abs.AbsoluteUri, 300);
            f.External = !DomainUtil.SameSite(abs.IdnHost, page.IdnHost);
            f.Insecure = abs.Scheme == Uri.UriSchemeHttp;
            return f;
        }

        private static void ReadMetaRefresh(string content, Uri baseUri, Uri page, HtmlScanResult r)
        {
            if (string.IsNullOrWhiteSpace(content)) return;
            Match m = RxRefresh.Match(content);
            if (!m.Success) return;

            r.MetaRefreshDelay = m.Groups[1].Value;
            string target = m.Groups[2].Success ? m.Groups[2].Value.Trim() : "";
            if (target.Length == 0) { r.MetaRefreshTarget = "(reloads the same page)"; return; }

            Uri abs = Resolve(baseUri, target);
            if (abs == null || !IsWeb(abs)) { r.MetaRefreshTarget = Clean(target, 200); return; }
            r.MetaRefreshTarget = Clean(abs.AbsoluteUri, 300);
            r.MetaRefreshExternal = !DomainUtil.SameSite(abs.IdnHost, page.IdnHost);
        }

        private static void BuildWarnings(Uri page, HtmlScanResult r)
        {
            foreach (HtmlForm f in r.Forms.Where(x => x.HasPassword))
            {
                if (f.External)
                    r.Warnings.Add("A form with a password field sends the data to a different site: " + f.Action);
                else if (f.Insecure)
                    r.Warnings.Add("A form with a password field sends the data over plain HTTP: " + f.Action);
            }
            if (r.PasswordFields > 0 && page.Scheme == Uri.UriSchemeHttp)
                r.Warnings.Add("The page asks for a password but was loaded over plain HTTP.");
            if (r.MetaRefreshExternal)
                r.Warnings.Add("The page sends the visitor to another site by itself" +
                               (r.MetaRefreshDelay != null ? " after " + r.MetaRefreshDelay + " second(s)" : "") +
                               ": " + r.MetaRefreshTarget);
            foreach (HtmlFrame fr in r.Frames.Where(x => x.Hidden && x.External))
                r.Warnings.Add("A hidden frame loads content from another site: " + fr.Src);
        }

        // ---------------- tiện ích ----------------

        // Lấy giá trị thuộc tính (không phân biệt hoa thường). null nếu không có.
        internal static string Attr(string attrs, string name)
        {
            if (string.IsNullOrEmpty(attrs)) return null;
            foreach (Match m in RxAttr.Matches(attrs))
            {
                if (!string.Equals(m.Groups[1].Value, name, StringComparison.OrdinalIgnoreCase)) continue;
                for (int g = 2; g <= 4; g++)
                    if (m.Groups[g].Success) return WebUtility.HtmlDecode(m.Groups[g].Value);
            }
            return null;
        }

        private static bool IsHiddenFrame(string attrs)
        {
            if (Regex.IsMatch(attrs, @"(^|\s)hidden(\s|=|$)", Opt, RxTimeout)) return true;

            foreach (string dim in new[] { "width", "height" })
            {
                string v = Attr(attrs, dim);
                int n;
                if (v != null && int.TryParse(v.Trim().TrimEnd('p', 'x', 'P', 'X'), NumberStyles.Integer, CultureInfo.InvariantCulture, out n) && n <= 1)
                    return true;
            }

            string style = (Attr(attrs, "style") ?? "").Replace(" ", "").ToLowerInvariant();
            return style.Contains("display:none") || style.Contains("visibility:hidden")
                   || style.Contains("width:0") || style.Contains("height:0");
        }

        private static Uri Resolve(Uri baseUri, string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            Uri abs;
            return Uri.TryCreate(baseUri, value.Trim(), out abs) ? abs : null;
        }

        private static bool IsWeb(Uri u)
        {
            return u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps;
        }

        // Bỏ ký tự điều khiển và ký tự định dạng hai chiều (RTL override...) để văn bản của trang
        // không thể đánh lừa mắt người đọc; gộp khoảng trắng và cắt độ dài.
        internal static string Clean(string s, int max)
        {
            if (s == null) return null;
            var sb = new StringBuilder(Math.Min(s.Length, max));
            bool space = false;
            foreach (char c in s)
            {
                UnicodeCategory cat = char.GetUnicodeCategory(c);
                if (char.IsWhiteSpace(c) || cat == UnicodeCategory.LineSeparator || cat == UnicodeCategory.ParagraphSeparator)
                {
                    if (!space && sb.Length > 0) sb.Append(' ');
                    space = true;
                    continue;
                }
                if (cat == UnicodeCategory.Control || cat == UnicodeCategory.Format) continue;
                space = false;
                sb.Append(c);
                if (sb.Length >= max) { sb.Append("..."); break; }
            }
            return sb.ToString().Trim();
        }
    }
}
