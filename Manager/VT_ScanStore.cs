using System.Collections.Concurrent;

namespace Project_check_URL
{
    internal static class VT_ScanStore
    {
        private static readonly ConcurrentDictionary<string, string> Cache = new ConcurrentDictionary<string, string>();
        public static void Save(string analysisId, string rawJson)
        {
            Cache[analysisId] = rawJson;
        }

        public static string Load(string analysisId)
        {
            string json;
            return Cache.TryGetValue(analysisId, out json) ? json : null;
        }
    }
}