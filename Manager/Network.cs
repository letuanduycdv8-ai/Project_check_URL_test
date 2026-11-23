using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.NetworkInformation;


namespace Project_check_URL
{
    public static class Check_Internet
    {
        private static readonly HttpClient Http =
            new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        private static async Task<bool> ProbeAsync(string url, Func<string, bool> isExpected) // chỗ func này là lambda nhận vào string và trả về bool
        {
            try
            {
                using (HttpResponseMessage response = await Http.GetAsync(url))
                {
                    string body = await response.Content.ReadAsStringAsync();
                    return isExpected(body);
                }
            }
            catch (HttpRequestException) // hết thời gian, DNS lỗi, bị chặn... đều coi là offline, cho trường hợp mạng chập chờn
            {
                return false;
            }
        }
        public static async Task<bool> IsOnlineAsync()
        {
            if (!NetworkInterface.GetIsNetworkAvailable()) return false;
            return await ProbeAsync("http://www.msftconnecttest.com/connecttest.txt",
                                    body => body.Trim() == "Microsoft Connect Test")
                || await ProbeAsync("http://clients3.google.com/generate_204",
                                    body => body.Length == 0);
        }
       
    }
}
