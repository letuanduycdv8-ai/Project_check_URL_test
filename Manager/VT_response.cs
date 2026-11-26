using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Script.Serialization;

namespace Project_check_URL
{
    internal class EngineVerdict
    {
        public string Engine { get; set; }
        public string Category { get; set; }   // malicious / suspicious / harmless / undetected / timeout
        public string Result { get; set; }     // phishing / malware / malicious / clean ...
        public string Method { get; set; }
    }

    // Dữ liệu có cấu trúc, trích từ JSON thô của GET /analyses/{id}
    internal class VtReport
    {
        public string AnalysisId { get; set; }
        public string Status { get; set; }
        public DateTime? ScanDateUtc { get; set; }
        public string Url { get; set; }
        public string UrlId { get; set; }
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public int Timeout { get; set; }
        public List<EngineVerdict> Engines { get; private set; }

        public VtReport() { Engines = new List<EngineVerdict>(); }

        public bool IsCompleted { get { return Status == "completed"; } }
        // Báo cáo có sẵn trên VirusTotal (không phải quét mới); AnalysisId do API_request đặt tiền tố "existing-"
        public bool IsExisting { get { return AnalysisId != null && AnalysisId.StartsWith("existing-", StringComparison.Ordinal); } }
        public int Responding { get { return Malicious + Suspicious + Harmless; } }
        public int TotalEngines { get { return Responding + Undetected + Timeout; } }
        public string VtPageUrl
        {
            get { return string.IsNullOrEmpty(UrlId) ? null : "https://www.virustotal.com/gui/url/" + UrlId; }
        }

        public List<EngineVerdict> Flagged(string category)
        {
            return Engines.Where(e => string.Equals(e.Category, category, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        public static VtReport Parse(string analysisId, string json)
        {
            var r = new VtReport { AnalysisId = analysisId, Status = "unknown" };
            var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            var root = ser.Deserialize<Dictionary<string, object>>(json);

            var urlInfo = Obj(Obj(root, "meta"), "url_info");
            if (urlInfo != null) { r.Url = Str(urlInfo, "url"); r.UrlId = Str(urlInfo, "id"); }

            var attrs = Obj(Obj(root, "data"), "attributes");
            if (attrs == null) return r;

            r.Status = Str(attrs, "status") ?? "unknown";

            long unix;
            if (long.TryParse(Str(attrs, "date"), out unix))
                r.ScanDateUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unix);

            var stats = Obj(attrs, "stats");
            r.Malicious = Int(stats, "malicious");
            r.Suspicious = Int(stats, "suspicious");
            r.Harmless = Int(stats, "harmless");
            r.Undetected = Int(stats, "undetected");
            r.Timeout = Int(stats, "timeout");

            var results = Obj(attrs, "results");
            if (results != null)
            {
                foreach (var kv in results)
                {
                    var e = kv.Value as Dictionary<string, object>;
                    if (e == null) continue;
                    r.Engines.Add(new EngineVerdict
                    {
                        Engine = Str(e, "engine_name") ?? kv.Key,
                        Category = Str(e, "category"),
                        Result = Str(e, "result"),
                        Method = Str(e, "method")
                    });
                }
            }
            return r;
        }

        private static Dictionary<string, object> Obj(Dictionary<string, object> d, string k)
        {
            object v;
            return d != null && d.TryGetValue(k, out v) ? v as Dictionary<string, object> : null;
        }
        private static string Str(Dictionary<string, object> d, string k)
        {
            object v;
            return d != null && d.TryGetValue(k, out v) && v != null ? v.ToString() : null;
        }
        private static int Int(Dictionary<string, object> d, string k)
        {
            int n;
            return int.TryParse(Str(d, k), out n) ? n : 0;
        }
    }

    internal class VtVerdict
    {
        public string Level { get; set; }        // Safe / Warning / Danger / Unknown
        public string Confidence { get; set; }   // None / Low / Medium / High
        public string Finding { get; set; }
        public string Assessment { get; set; }
        public List<string> Reasons { get; private set; }
        public VtVerdict() { Reasons = new List<string>(); }
    }

    internal static class VtVerdictBuilder
    {
        // Tên phải khớp key trong "results" của JSON thật, hãy đối chiếu lại
        private static readonly HashSet<string> Trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Google Safebrowsing", "Kaspersky", "BitDefender", "ESET", "Sophos",
            "Fortinet", "Avira", "Webroot", "Phishtank", "OpenPhish"
        };
        private const int MinResponding = 10;

        public static VtVerdict Build(VtReport r)
        {
            var v = new VtVerdict();
            v.Finding = r.Malicious + " malicious, " + r.Suspicious + " suspicious (of " + r.TotalEngines + " engines)";

            // Case 1: chưa quét xong
            if (!r.IsCompleted)
            {
                v.Level = "Unknown"; v.Confidence = "None";
                v.Assessment = "The scan has not finished (status: " + r.Status + "). No conclusion can be drawn yet. Try again in a moment.";
                return v;
            }

            var bad = r.Flagged("malicious");
            var sus = r.Flagged("suspicious");
            foreach (var e in bad.Concat(sus)) v.Reasons.Add(Explain(e));

            bool trustedHit = bad.Any(e => Trusted.Contains(e.Engine));
            string label = DominantLabel(bad);
            string names = Names(bad);
            string timeoutNote = r.Timeout >= 10 ? " " + r.Timeout + " engines did not respond in time." : "";

            // Case 2: Danger
            if (r.Malicious >= 3 || (r.Malicious >= 1 && trustedHit))
            {
                v.Level = "Danger"; v.Confidence = "High";
                string by = names.Length > 0 ? names : r.Malicious + " engines";
                if (label == "phishing")
                    v.Assessment = "High risk. " + by + " classified this URL as phishing, usually a fake page built to steal logins or personal data. Do not open it or enter any information. If it came from a message or an email, report it.";
                else if (label == "malware")
                    v.Assessment = "High risk. " + by + " reported this URL as distributing malware. Do not open it or download anything from it. If it came from a message or an email, report it.";
                else
                    v.Assessment = "High risk. " + by + " flagged this URL as malicious. Do not open it or enter any information. If it came from a message or an email, report it.";
                return v;
            }

            // Case 3: Warning do 1-2 engine báo malicious, không có engine uy tín
            if (r.Malicious >= 1)
            {
                v.Level = "Warning";
                v.Confidence = r.Malicious == 2 ? "Medium" : "Low";
                // results[] có thể rỗng dù stats báo có engine gắn cờ: khi đó chỉ nêu số lượng
                string who = names.Length > 0 ? names : (r.Malicious == 1 ? "1 engine" : r.Malicious + " engines");
                v.Assessment = (r.Malicious == 2 ? "Medium" : "Low") + " confidence. Only " + who + " flagged this URL as " + label
                    + (r.Suspicious > 0 ? ", and " + r.Suspicious + " more marked it suspicious" : "")
                    + ", while " + r.Harmless + " engines reported it as harmless. A few detections can be a false positive, especially on well-known or developer sites. Check that the address is what you expect and avoid entering personal data until you are sure." + timeoutNote;
                return v;
            }

            // Case 4: Warning do chỉ có suspicious
            if (r.Suspicious >= 1)
            {
                v.Level = "Warning"; v.Confidence = "Low";
                string susWho = sus.Count > 0 ? Names(sus) : (r.Suspicious == 1 ? "1 engine" : r.Suspicious + " engines");
                v.Assessment = "Low confidence. " + susWho + " marked this URL as suspicious, but no engine confirmed it as malicious. Treat it with caution and avoid entering personal data." + timeoutNote;
                return v;
            }

            // Case 5: không ai gắn cờ nhưng độ phủ thấp
            if (r.Responding < MinResponding)
            {
                v.Level = "Unknown"; v.Confidence = "Low";
                v.Assessment = "No engine flagged this URL, but only " + r.Responding + " engines returned a verdict, so coverage is low. This is common for new or rarely seen URLs. Do not treat it as confirmed safe." + timeoutNote;
                return v;
            }

            // Case 6: Safe
            v.Level = "Safe"; v.Confidence = "Medium";
            v.Assessment = "No engine flagged this URL (" + r.Harmless + " reported it as harmless). This lowers the risk but is not a guarantee: new or targeted pages may not be listed yet. Stay careful on pages that ask for a password or payment details." + timeoutNote;
            return v;
        }

        private static string DominantLabel(List<EngineVerdict> bad)
        {
            var all = string.Join(" ", bad.Select(e => (e.Result ?? "").ToLowerInvariant()));
            if (all.Contains("phish")) return "phishing";
            if (all.Contains("malware") || all.Contains("trojan") || all.Contains("virus") || all.Contains("ransom")) return "malware";
            if (all.Contains("spam")) return "spam";
            return "malicious";
        }

        private static string Names(List<EngineVerdict> list)
        {
            var n = list.Select(e => e.Engine).Take(5).ToList();
            string s = string.Join(", ", n);
            if (list.Count > 5) s += " and " + (list.Count - 5) + " more";
            return s;
        }

        // "Engine: nhãn - nghĩa" (dùng cho Reasons)
        private static string Explain(EngineVerdict e)
        {
            return e.Engine + ": " + e.Result + " - " + Meaning(e);
        }

        // Nghĩa của nhãn. VirusTotal không cung cấp lý do chi tiết hơn
        internal static string Meaning(EngineVerdict e)
        {
            string res = (e.Result ?? "").ToLowerInvariant();
            string meaning;
            if (res.Contains("phish")) meaning = "reported as a phishing page (a fake page imitating a real service to steal data)";
            else if (res.Contains("malware") || res.Contains("trojan") || res.Contains("virus")) meaning = "reported as hosting or distributing malicious software";
            else if (res.Contains("spam")) meaning = "reported as a source of spam";
            else if (string.Equals(e.Category, "suspicious", StringComparison.OrdinalIgnoreCase)) meaning = "looks unusual but is not confirmed as harmful";
            else meaning = "flagged by this engine's blocklist; VirusTotal does not give a more specific reason";
            return meaning;
        }
    }

    // ------------------------------------------------------------------
    // Thông tin lấy từ đối tượng URL của VirusTotal (GET /urls/{id}):
    // điểm cộng đồng, bình chọn, phân loại, lần đầu thấy, số lần gửi...
    // Mọi trường đều có thể thiếu nên đọc phòng thủ.
    // ------------------------------------------------------------------
    internal class VtUrlInfo
    {
        public int? Reputation { get; set; }
        public bool HasVotes { get; set; }
        public int VotesHarmless { get; set; }
        public int VotesMalicious { get; set; }
        public List<KeyValuePair<string, string>> Categories { get; private set; }
        public List<string> Tags { get; private set; }
        public List<string> ThreatNames { get; private set; }
        public DateTime? FirstSeenUtc { get; set; }
        public DateTime? LastSubmissionUtc { get; set; }
        public DateTime? LastAnalysisUtc { get; set; }
        public int TimesSubmitted { get; set; }
        public string Title { get; set; }
        public string LastFinalUrl { get; set; }
        public int? LastHttpCode { get; set; }

        public VtUrlInfo()
        {
            Categories = new List<KeyValuePair<string, string>>();
            Tags = new List<string>();
            ThreatNames = new List<string>();
        }

        private static readonly string[] RiskyWords =
            { "phish", "malware", "malicious", "suspicious", "spam", "scam", "fraud", "newly registered", "newly observed" };

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static VtUrlInfo Parse(string json)
        {
            var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            var root = ser.Deserialize<Dictionary<string, object>>(json);
            var attrs = Obj(Obj(root, "data"), "attributes");
            var info = new VtUrlInfo();
            if (attrs == null) return info;

            long n;
            if (Long(attrs, "reputation", out n)) info.Reputation = (int)n;

            var votes = Obj(attrs, "total_votes");
            if (votes != null)
            {
                info.HasVotes = true;
                if (Long(votes, "harmless", out n)) info.VotesHarmless = (int)n;
                if (Long(votes, "malicious", out n)) info.VotesMalicious = (int)n;
            }

            var cats = Obj(attrs, "categories");
            if (cats != null)
                foreach (var kv in cats)
                    if (kv.Value != null) info.Categories.Add(new KeyValuePair<string, string>(kv.Key, kv.Value.ToString()));

            info.Tags.AddRange(Strings(attrs, "tags"));
            info.ThreatNames.AddRange(Strings(attrs, "threat_names"));

            info.FirstSeenUtc = Time(attrs, "first_submission_date");
            info.LastSubmissionUtc = Time(attrs, "last_submission_date");
            info.LastAnalysisUtc = Time(attrs, "last_analysis_date");
            if (Long(attrs, "times_submitted", out n)) info.TimesSubmitted = (int)n;

            info.Title = HtmlScan.Clean(Str(attrs, "title"), 200);
            info.LastFinalUrl = HtmlScan.Clean(Str(attrs, "last_final_url"), 300);
            if (Long(attrs, "last_http_response_code", out n)) info.LastHttpCode = (int)n;
            return info;
        }

        // Những điểm đáng ngại rút ra từ dữ liệu cộng đồng / phân loại. Rỗng nếu không có gì.
        public List<string> RiskReasons()
        {
            var reasons = new List<string>();

            if (Reputation.HasValue && Reputation.Value < 0)
                reasons.Add("The VirusTotal community reputation score is negative (" + Reputation.Value + ").");

            if (HasVotes && VotesMalicious > VotesHarmless)
                reasons.Add("More community votes say malicious (" + VotesMalicious + ") than harmless (" + VotesHarmless + ").");

            List<string> risky = Categories
                .Where(c => RiskyWords.Any(w => (c.Value ?? "").ToLowerInvariant().Contains(w)))
                .Select(c => c.Key + ": " + HtmlScan.Clean(c.Value, 60))
                .Take(3).ToList();
            if (risky.Count > 0)
                reasons.Add("Categorisation services label it as " + string.Join("; ", risky) + ".");

            if (ThreatNames.Count > 0)
                reasons.Add("VirusTotal lists threat names: " + string.Join(", ", ThreatNames.Take(5).Select(x => HtmlScan.Clean(x, 60))) + ".");

            return reasons;
        }

        private static Dictionary<string, object> Obj(Dictionary<string, object> d, string k)
        {
            object v;
            return d != null && d.TryGetValue(k, out v) ? v as Dictionary<string, object> : null;
        }
        private static string Str(Dictionary<string, object> d, string k)
        {
            object v;
            return d != null && d.TryGetValue(k, out v) && v != null ? v.ToString() : null;
        }
        private static bool Long(Dictionary<string, object> d, string k, out long n)
        {
            return long.TryParse(Str(d, k), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out n);
        }
        private static DateTime? Time(Dictionary<string, object> d, string k)
        {
            long unix;
            return Long(d, k, out unix) && unix > 0 ? (DateTime?)Epoch.AddSeconds(unix) : null;
        }
        private static IEnumerable<string> Strings(Dictionary<string, object> d, string k)
        {
            object v;
            var list = new List<string>();
            if (d == null || !d.TryGetValue(k, out v) || !(v is System.Collections.IEnumerable) || v is string) return list;
            foreach (object item in (System.Collections.IEnumerable)v)
                if (item != null) list.Add(HtmlScan.Clean(item.ToString(), 80));
            return list;
        }
    }

    // Kết luận của thẻ "Reputation" (gom một chỗ để test được, HomeView chỉ gán vào CheckItem)
    internal class ReputationEval
    {
        public string Finding { get; set; }
        public string Level { get; set; }
        public string Assessment { get; set; }

        public static ReputationEval Evaluate(VtReport r, VtVerdict v, VtUrlInfo u)
        {
            var e = new ReputationEval
            {
                // cách tính cũ giữ nguyên: dùng khi chưa có dữ liệu cộng đồng
                Finding = r.Harmless + " harmless, " + r.Undetected + " undetected",
                Level = (r.Malicious + r.Suspicious) > 0 || v.Level == "Unknown" ? "Warning" : "Safe",
                Assessment = v.Level == "Unknown" ? v.Assessment : null
            };

            if (u == null) return e;

            // "Reputation" trước đây chỉ đếm engine; nay hiện điểm và bình chọn thật của cộng đồng
            if (u.Reputation.HasValue || u.HasVotes)
            {
                string score = u.Reputation.HasValue ? "Score " + u.Reputation.Value : "No score";
                e.Finding = u.HasVotes
                    ? score + "  ·  votes " + u.VotesHarmless + " harmless / " + u.VotesMalicious + " malicious"
                    : score;
            }

            List<string> reasons = u.RiskReasons();
            if (reasons.Count > 0)
            {
                e.Level = "Warning";
                string extra = string.Join(" ", reasons);
                e.Assessment = string.IsNullOrEmpty(e.Assessment) ? extra : e.Assessment + " " + extra;
            }
            return e;
        }
    }
}
