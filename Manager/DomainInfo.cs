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
}
