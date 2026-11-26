using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Project_check_URL.View;

namespace Project_check_URL
{
    // ------------------------------------------------------------------
    // Tiện ích về tên miền dùng chung cho phân tích redirect / HTML / RDAP
    // ------------------------------------------------------------------
    internal static class DomainUtil
    {
        // Dịch vụ rút gọn link phổ biến: đích thật của link bị che
        private static readonly HashSet<string> Shorteners =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "v.gd", "ow.ly", "buff.ly",
                "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "rb.gy", "tiny.cc", "lnkd.in",
                "bit.do", "s.id", "adf.ly", "shorte.st", "qr.net", "urlz.fr", "tr.ee", "rebrand.ly"
            };

        // Tên miền đăng ký được (eTLD+1) dùng bảng hậu tố của Offline_check. Host là IP thì trả nguyên host.
        public static string Registrable(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return null;
            host = host.Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
            IPAddress ip;
            if (IPAddress.TryParse(host, out ip)) return host;
            return Offline_check.GetRegistrableDomain(host.Split('.'));
        }

        public static bool SameSite(string hostA, string hostB)
        {
            return string.Equals(Registrable(hostA), Registrable(hostB), StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsShortener(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            string reg = Registrable(host);
            return reg != null && Shorteners.Contains(reg);
        }
    }

    // ------------------------------------------------------------------
    // Tuổi tên miền qua RDAP (miễn phí, không cần API key).
    // Chỉ chạy ở chế độ Online. Tên miền đang kiểm tra được gửi tới rdap.org.
    // ------------------------------------------------------------------
    internal class DomainAgeResult
    {
        public string Domain { get; set; }
        public string Source { get; set; }
        public DateTime? Registered { get; set; }
        public DateTime? LastChanged { get; set; }
        public DateTime? Expires { get; set; }
        public string Error { get; set; }

        public int? AgeDays
        {
            get
            {
                if (!Registered.HasValue) return null;
                return Math.Max(0, (int)(DateTime.UtcNow - Registered.Value).TotalDays);
            }
        }

        public bool IsNew { get { return AgeDays.HasValue && AgeDays.Value < NewDomainDays; } }

        public const int NewDomainDays = 30;

        // Nội dung đánh giá khi tên miền quá mới; null nếu không có gì đáng nói
        public string Assessment
        {
            get
            {
                if (!IsNew) return null;
                int d = AgeDays.Value;
                return "This domain was registered " + (d == 0 ? "today" : d + (d == 1 ? " day ago" : " days ago")) +
                       ". Phishing and scam sites very often use brand-new domains. " +
                       "Be careful with any login, payment or download on it.";
            }
        }

        public static DomainAgeResult Failed(string domain, string error)
        {
            return new DomainAgeResult { Domain = domain, Source = "rdap.org", Error = error };
        }
    }

    internal static class DomainAgeClient
    {
        private static readonly HttpClient Client = CreateClient();

        private static HttpClient CreateClient()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 3,
                UseCookies = false
            };
            var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10), MaxResponseContentBufferSize = 512 * 1024 };
            c.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/rdap+json, application/json");
            c.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "LinkGuard-URL-Checker/1.0");
            return c;
        }

        public static async Task<DomainAgeResult> LookupAsync(string idnHost, CancellationToken token)
        {
            string host = (idnHost ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            IPAddress ip;
            if (host.Length == 0 || IPAddress.TryParse(host.Trim('[', ']'), out ip))
                return DomainAgeResult.Failed(host, "The host is an IP address, so there is no domain registration.");

            string[] labels = host.Split('.');
            string reg = Offline_check.GetRegistrableDomain(labels);
            int regLabels = reg.Split('.').Length;

            var candidates = new List<string> { reg };
            // Hậu tố 2 cấp chưa có trong bảng: nếu bản ghi của "co.uk" kiểu đó không tồn tại, thử thêm một nhãn
            if (labels.Length > regLabels)
                candidates.Add(string.Join(".", labels.Skip(labels.Length - (regLabels + 1))));

            string lastError = "No registration record was found.";
            foreach (string candidate in candidates)
            {
                token.ThrowIfCancellationRequested();
                using (var request = new HttpRequestMessage(HttpMethod.Get, "https://rdap.org/domain/" + candidate))
                using (HttpResponseMessage response = await Client.SendAsync(request, token).ConfigureAwait(false))
                {
                    if (response.StatusCode == HttpStatusCode.NotFound) { lastError = "No registration record was found for " + candidate + "."; continue; }
                    if ((int)response.StatusCode == 429) return DomainAgeResult.Failed(candidate, "The RDAP service is busy (rate limit). Try again later.");
                    if (!response.IsSuccessStatusCode) return DomainAgeResult.Failed(candidate, "RDAP error " + (int)response.StatusCode + ".");

                    string json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    DomainAgeResult r = Parse(candidate, json);
                    if (r.Registered.HasValue || r.Error != null) return r;
                    lastError = "The record has no registration date.";
                }
            }
            return DomainAgeResult.Failed(reg, lastError);
        }

        // Đọc phần tử events của RDAP (tách riêng để test được)
        internal static DomainAgeResult Parse(string domain, string json)
        {
            var result = new DomainAgeResult { Domain = domain, Source = "rdap.org" };
            try
            {
                var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                var root = ser.Deserialize<Dictionary<string, object>>(json);
                object ev;
                if (root == null || !root.TryGetValue("events", out ev) || !(ev is System.Collections.IEnumerable))
                    return result;

                foreach (object item in (System.Collections.IEnumerable)ev)
                {
                    var e = item as Dictionary<string, object>;
                    if (e == null) continue;
                    object action, date;
                    if (!e.TryGetValue("eventAction", out action) || !e.TryGetValue("eventDate", out date)) continue;

                    DateTime t;
                    if (!DateTime.TryParse(Convert.ToString(date, CultureInfo.InvariantCulture), CultureInfo.InvariantCulture,
                            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                        continue;

                    switch ((Convert.ToString(action) ?? "").ToLowerInvariant())
                    {
                        case "registration": result.Registered = t; break;
                        case "last changed": result.LastChanged = t; break;
                        case "expiration": result.Expires = t; break;
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = "Could not read the RDAP answer (" + ex.GetType().Name + ").";
            }
            return result;
        }
    }
}
