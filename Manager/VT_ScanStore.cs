using System.Collections.Concurrent;

namespace Project_check_URL
{
    // Lưu response thô của VirusTotal trong RAM, chỉ tồn tại trong phiên chạy app
    internal static class VT_ScanStore
    {
        private static readonly ConcurrentDictionary<string, string> Cache = new ConcurrentDictionary<string, string>();
        public static void Save(string analysisId, string rawJson)
        {
            Cache[analysisId] = rawJson;
        }

        // Trả về null nếu chưa có
        public static string Load(string analysisId)
        {
            string json;
            return Cache.TryGetValue(analysisId, out json) ? json : null;
        }

        public static bool Exists(string analysisId)
        {
            return Cache.ContainsKey(analysisId);
        }

        // Gọi khi người dùng xóa kết quả hoặc muốn giải phóng bộ nhớ
        public static void Remove(string analysisId)
        {
            string ignored;
            Cache.TryRemove(analysisId, out ignored);
        }

        public static void Clear()
        {
            Cache.Clear();
        }
    }
}