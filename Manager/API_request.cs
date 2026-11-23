using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
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

        public bool IsCompleted
        {
            get { return Status == "completed"; }
        }
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

        // Gửi URL, chờ quét xong, trả về kết quả.
        // Mặc định poll 15 giây/lần để không vượt quota bản free (4 request/phút).
        public async Task<ScanResult> ScanUrlAsync(string url, int maxAttempts = 8, int delayMs = 15000)
        {
            if (string.IsNullOrWhiteSpace(url))
                throw new ArgumentException("URL không được để trống.", "url");

            string analysisId = await SubmitUrlAsync(url).ConfigureAwait(false);

            for (int i = 0; i < maxAttempts; i++)
            {
                await Task.Delay(delayMs).ConfigureAwait(false);

                ScanResult result = await GetAnalysisAsync(analysisId).ConfigureAwait(false);
                if (result.IsCompleted)
                    return result;
            }

            throw new ScanTimeoutException(
                "VirusTotal chưa quét xong (analysis ID: " + analysisId + "), hãy thử lại sau.",
                analysisId);
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
        private static async Task<string> SendAsync(HttpRequestMessage request)
        {
            using (HttpResponseMessage response = await ClientMng.Client.SendAsync(request).ConfigureAwait(false))
            {
                string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

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