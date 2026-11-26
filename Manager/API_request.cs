using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Project_check_URL
{
    internal class ScanResult
    {
        public string AnalysisId { get; set; }
        public string Status { get; set; }      // queued / in-progress / completed
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public int Timeout { get; set; }

        public DateTime? ScanDate { get; set; }          // giờ UTC VirusTotal hoàn tất phân tích
        public string ScannedUrl { get; set; }           // URL mà VirusTotal ghi nhận
        public string UrlId { get; set; }                // dùng để mở trang kết quả trên VirusTotal
        public string UrlObjectJson { get; set; }        // JSON của GET /urls/{id} (điểm cộng đồng, phân loại...), null nếu không lấy được
        public bool FromExistingReport { get; set; }     // true: dùng báo cáo có sẵn, không quét mới
        public List<EngineResult> Engines { get; private set; }

        public ScanResult()
        {
            Engines = new List<EngineResult>();
        }

        // Trang kết quả đầy đủ trên VirusTotal (null nếu response không có url id)
        public string ReportLink
        {
            get
            {
                return string.IsNullOrEmpty(UrlId)
                    ? null
                    : "https://www.virustotal.com/gui/url/" + UrlId;
            }
        }

        public bool IsCompleted
        {
            get { return Status == "completed"; }
        }
    }

    // Kết quả của một engine bảo mật trong VirusTotal
    internal class EngineResult
    {
        public string Engine { get; set; }
        public string Category { get; set; }   // malicious / suspicious / harmless / undetected / timeout ...
        public string Result { get; set; }     // vd "phishing", "clean", "unrated"
        public string Method { get; set; }     // vd "blacklist"
    }

    // Vượt quota (HTTP 429)
    internal class VirusTotalQuotaException : Exception
    {
        public TimeSpan? RetryAfter { get; private set; }

        public VirusTotalQuotaException(string message, TimeSpan? retryAfter)
            : base(message)
        {
            RetryAfter = retryAfter;
        }
    }

    // Quét chưa xong sau số lần thử tối đa; giữ lại ID để lấy kết quả sau
    internal class ScanTimeoutException : TimeoutException
    {
        public string AnalysisId { get; private set; }

        public ScanTimeoutException(string message, string analysisId)
            : base(message)
        {
            AnalysisId = analysisId;
        }
    }

    internal class API_request
    {
        private const string BaseUrl = "https://www.virustotal.com/api/v3";
        private readonly string _apiKey;

        public API_request(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new ArgumentException("API key không được để trống.", "apiKey");

            _apiKey = apiKey;
        }

        // Báo cáo có sẵn trên VirusTotal chỉ được dùng lại nếu mới hơn mức này
        private static readonly TimeSpan MaxExistingReportAge = TimeSpan.FromHours(24);

        // Lấy kết quả cho URL. Đường nhanh: nếu VirusTotal đã có báo cáo trong 24 giờ gần đây thì dùng luôn
        // (1 request, không phải đợi quét, đỡ quota). Nếu không thì gửi quét mới như trước.
        // Mặc định poll 15 giây/lần để không vượt quota bản free (4 request/phút).
        public async Task<ScanResult> ScanUrlAsync(string url, int maxAttempts = 8, int delayMs = 15000)
        {
            if (string.IsNullOrWhiteSpace(url))
                throw new ArgumentException("URL không được để trống.", "url");

            // 1) Có báo cáo mới sẵn chưa? Lỗi ở bước này không quan trọng, cứ quét mới.
            string existingJson = null;
            try { existingJson = await GetUrlObjectJsonAsync(UrlIdFromText(url)).ConfigureAwait(false); }
            catch (Exception) { existingJson = null; }

            ScanResult existing = TryBuildFromUrlObject(url, existingJson, DateTime.UtcNow);
            if (existing != null)
                return existing;

            // 2) Quét mới
            string analysisId = await SubmitUrlAsync(url).ConfigureAwait(false);

            for (int i = 0; i < maxAttempts; i++)
            {
                await Task.Delay(delayMs).ConfigureAwait(false);

                ScanResult result = await GetAnalysisAsync(analysisId).ConfigureAwait(false);
                if (result.IsCompleted)
                {
                    // 3) Lấy thêm điểm cộng đồng, phân loại... (không bắt buộc: lỗi thì bỏ qua)
                    try
                    {
                        string id = string.IsNullOrEmpty(result.UrlId) ? UrlIdFromText(url) : result.UrlId;
                        result.UrlObjectJson = await GetUrlObjectJsonAsync(id).ConfigureAwait(false);
                    }
                    catch (Exception) { result.UrlObjectJson = null; }
                    return result;
                }
            }

            throw new ScanTimeoutException(
                "VirusTotal chưa quét xong (analysis ID: " + analysisId + "), hãy thử lại sau.",
                analysisId);
        }

        // ID URL theo VirusTotal: base64 an toàn cho URL (+ -> -, / -> _), bỏ dấu "="
        internal static string UrlIdFromText(string url)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        // GET /urls/{id}: null nếu VirusTotal chưa từng thấy URL này (404)
        private async Task<string> GetUrlObjectJsonAsync(string urlId)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, BaseUrl + "/urls/" + urlId))
            {
                request.Headers.Add("x-apikey", _apiKey);
                return await SendAsync(request, true).ConfigureAwait(false);
            }
        }

        // Dựng kết quả từ đối tượng URL có sẵn. Trả null nếu thiếu dữ liệu hoặc báo cáo đã cũ
        // (khi đó phải quét mới). Dựng lại JSON dạng /analyses để dùng chung VtReport.Parse.
        internal static ScanResult TryBuildFromUrlObject(string url, string urlJson, DateTime nowUtc)
        {
            if (string.IsNullOrWhiteSpace(urlJson)) return null;

            try
            {
                Dictionary<string, object> root = Parse(urlJson);
                Dictionary<string, object> data = GetObject(root, "data");
                Dictionary<string, object> attrs = GetObject(data, "attributes");
                if (attrs == null) return null;

                Dictionary<string, object> stats = GetObject(attrs, "last_analysis_stats");
                Dictionary<string, object> results = GetObject(attrs, "last_analysis_results");
                object date;
                if (stats == null || stats.Count == 0 || results == null || results.Count == 0 ||
                    !attrs.TryGetValue("last_analysis_date", out date) || date == null)
                    return null;

                long unix = Convert.ToInt64(date);
                DateTime analysed = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unix);
                if (analysed > nowUtc.AddMinutes(5) || nowUtc - analysed > MaxExistingReportAge)
                    return null;

                string urlId = GetString(data, "id") ?? UrlIdFromText(url);
                var synthetic = new Dictionary<string, object>
                {
                    { "data", new Dictionary<string, object> { { "attributes", new Dictionary<string, object> {
                        { "status", "completed" }, { "date", unix }, { "stats", stats }, { "results", results } } } } },
                    { "meta", new Dictionary<string, object> { { "url_info", new Dictionary<string, object> {
                        { "id", urlId }, { "url", GetString(attrs, "url") ?? url } } } } }
                };

                string json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize(synthetic);
                string analysisId = "existing-" + urlId;

                ScanResult r = ParseSummary(analysisId, json);
                if (!r.IsCompleted) return null;

                VT_ScanStore.Save(analysisId, json);
                r.UrlObjectJson = urlJson;
                r.FromExistingReport = true;
                return r;
            }
            catch (Exception)
            {
                return null;     // dữ liệu lạ: quét mới cho chắc
            }
        }

        // Bước 1: gửi URL, nhận analysis ID
        public async Task<string> SubmitUrlAsync(string url)
        {
            var form = new FormUrlEncodedContent(
                new Dictionary<string, string> { { "url", url } });

            using (var request = new HttpRequestMessage(HttpMethod.Post, BaseUrl + "/urls"))
            {
                request.Headers.Add("x-apikey", _apiKey);
                request.Content = form;

                string json = await SendAsync(request).ConfigureAwait(false);

                Dictionary<string, object> root = Parse(json);
                Dictionary<string, object> data = GetObject(root, "data");

                object id;
                if (data == null || !data.TryGetValue("id", out id) || id == null)
                    throw new InvalidOperationException("Không đọc được analysis ID từ phản hồi.");

                return id.ToString();
            }
        }

        // Bước 2: lấy kết quả quét
        public async Task<ScanResult> GetAnalysisAsync(string analysisId)
        {
            using (var request = new HttpRequestMessage(
                HttpMethod.Get, BaseUrl + "/analyses/" + analysisId))
            {
                request.Headers.Add("x-apikey", _apiKey);

                string json = await SendAsync(request).ConfigureAwait(false);

                ScanResult result = ParseSummary(analysisId, json);
                

                // Chỉ lưu khi quét xong, tránh ghi đè bằng bản queued/in-progress
                if (result.IsCompleted)
                    VT_ScanStore.Save(analysisId, json);

                return result;
            }
        }
        public static ScanResult ParseSummary(string analysisId, string json)
        {
            Dictionary<string, object> root = Parse(json);
            Dictionary<string, object> attrs = GetObject(GetObject(root, "data"), "attributes");

            var result = new ScanResult { AnalysisId = analysisId, Status = "unknown" };

            if (attrs != null)
            {
                object status;
                if (attrs.TryGetValue("status", out status) && status != null)
                    result.Status = status.ToString();

                Dictionary<string, object> stats = GetObject(attrs, "stats");
                result.Malicious = GetInt(stats, "malicious");
                result.Suspicious = GetInt(stats, "suspicious");
                result.Harmless = GetInt(stats, "harmless");
                result.Undetected = GetInt(stats, "undetected");
                result.Timeout = GetInt(stats, "timeout");

                // Ngày phân tích (unix giây, UTC)
                object date;
                if (attrs.TryGetValue("date", out date) && date != null)
                {
                    try
                    {
                        result.ScanDate = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                            .AddSeconds(Convert.ToInt64(date));
                    }
                    catch (Exception) { }
                }

                // Kết quả từng engine
                Dictionary<string, object> engines = GetObject(attrs, "results");
                if (engines != null)
                {
                    foreach (KeyValuePair<string, object> kv in engines)
                    {
                        var e = kv.Value as Dictionary<string, object>;
                        if (e == null) continue;

                        result.Engines.Add(new EngineResult
                        {
                            Engine = GetString(e, "engine_name") ?? kv.Key,
                            Category = GetString(e, "category") ?? "unknown",
                            Result = GetString(e, "result"),
                            Method = GetString(e, "method")
                        });
                    }
                    result.Engines.Sort((a, b) => string.Compare(a.Engine, b.Engine, StringComparison.OrdinalIgnoreCase));
                }
            }

            // URL mà VirusTotal đã phân tích (meta.url_info)
            Dictionary<string, object> urlInfo = GetObject(GetObject(root, "meta"), "url_info");
            if (urlInfo != null)
            {
                result.UrlId = GetString(urlInfo, "id");
                result.ScannedUrl = GetString(urlInfo, "url");
            }

            return result;
        }

        // ---------- JSON helpers ----------

        private static Dictionary<string, object> Parse(string json)
        {
            var serializer = new JavaScriptSerializer();
            return serializer.Deserialize<Dictionary<string, object>>(json);
        }

        private static Dictionary<string, object> GetObject(Dictionary<string, object> parent, string key)
        {
            object value;
            if (parent != null && parent.TryGetValue(key, out value))
                return value as Dictionary<string, object>;
            return null;
        }

        private static string GetString(Dictionary<string, object> obj, string key)
        {
            object value;
            if (obj == null || !obj.TryGetValue(key, out value) || value == null)
                return null;
            return value.ToString();
        }

        private static int GetInt(Dictionary<string, object> obj, string key)
        {
            object value;
            if (obj == null || !obj.TryGetValue(key, out value) || value == null)
                return 0;

            try { return Convert.ToInt32(value); }
            catch (Exception) { return 0; }
        }

        // Lấy error.message từ JSON lỗi của VirusTotal, nếu không được thì trả nguyên body
        private static string ExtractErrorMessage(string body)
        {
            try
            {
                Dictionary<string, object> error = GetObject(Parse(body), "error");
                object code, message;
                if (error != null && error.TryGetValue("message", out message) && message != null)
                {
                    error.TryGetValue("code", out code);
                    return (code != null ? code + ": " : "") + message;
                }
            }
            catch (Exception)
            {
                // body không phải JSON, dùng nguyên văn
            }
            return body;
        }

        // ---------- HTTP ----------

        // Gửi request và xử lý lỗi HTTP
        // nullOn404 = true: 404 (chưa có dữ liệu) trả về null thay vì ném lỗi
        private static async Task<string> SendAsync(HttpRequestMessage request, bool nullOn404 = false)
        {
            using (HttpResponseMessage response = await ClientMng.Client.SendAsync(request).ConfigureAwait(false))
            {
                string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (nullOn404 && response.StatusCode == HttpStatusCode.NotFound)
                    return null;

                if (response.IsSuccessStatusCode)
                    return body;

                switch (response.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        throw new InvalidOperationException("API key không hợp lệ.");

                    case (HttpStatusCode)429:
                        TimeSpan? retryAfter = null;
                        if (response.Headers.RetryAfter != null)
                            retryAfter = response.Headers.RetryAfter.Delta;
                        throw new VirusTotalQuotaException(
                            "Vượt quota VirusTotal, hãy đợi rồi thử lại.", retryAfter);

                    default:
                        throw new HttpRequestException(
                            "VirusTotal error " + (int)response.StatusCode + ": " + ExtractErrorMessage(body));
                }
            }
        }
    }
}