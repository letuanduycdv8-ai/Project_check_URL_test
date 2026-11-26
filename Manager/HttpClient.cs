using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Project_check_URL
{
    internal class HttpProbeResult
    {
        public string Url { get; set; }
        public string FinalUrl { get; set; }
        public int StatusCode { get; set; }
        public string ReasonPhrase { get; set; }
        public string ContentType { get; set; }        // только media type, например "text/html"
        public string RawContentType { get; set; }     // исходное значение заголовка, например "text/html; charset=utf-8"
        public Dictionary<string, string> Headers { get; set; }
        public List<string> RedirectChain { get; set; }
        public List<HttpHop> Hops { get; set; }        // детали каждого шага, где был получен ответ
        public string Error { get; set; }
        public DateTime ProbedAt { get; set; }         // время UTC начала проверки

        public HttpProbeResult()
        {
            Headers = new Dictionary<string, string>();
            RedirectChain = new List<string>();
            Hops = new List<HttpHop>();
        }
    }

    // Один шаг в цепочке перенаправлений (один GET-запрос и получение заголовков)
    internal class HttpHop
    {
        public string Url { get; set; }
        public string Ips { get; set; }                // разрешённые и проверенные IP, через ", "
        public int StatusCode { get; set; }
        public string ReasonPhrase { get; set; }
        public string Location { get; set; }           // заголовок Location, если есть

        // только для https
        public string TlsProtocol { get; set; }
        public string CertSubject { get; set; }
        public string CertIssuer { get; set; }
        public DateTime? CertNotBefore { get; set; }
        public DateTime? CertNotAfter { get; set; }
    }

    // Версия для .NET Framework 4.7.2 / 4.8 (C# 7.3).
    // HttpClient в .NET Framework не позволяет вмешиваться в этап соединения, поэтому проверка URL
    // сама открывает TCP-соединение к УЖЕ проверенному IP, сама выполняет TLS (если https) и сама отправляет/читает HTTP/1.1.
    // Читаются только заголовки, тело не читается.
    internal static class ClientMng
    {
        private const int MaxRedirects = 5;
        private const int MaxHeaderValueLength = 2000;
        private const int MaxHeaderBlockBytes = 64 * 1024;
        private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(30);

        private const string BrowserUserAgent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        // Используется для VirusTotal API: обращается только к фиксированному адресу, поэтому блокировка IP не нужна
        public static readonly HttpClient Client = CreateApiClient("Project-check-URL/1.0");

        private static HttpClient CreateApiClient(string userAgent)
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
            return client;
        }

        // ===== Сырой результат одной отправки =====
        private sealed class RawResponse
        {
            public int StatusCode;
            public string ReasonPhrase;
            public Dictionary<string, string> Headers =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            public string TlsProtocol;
            public string CertSubject;
            public string CertIssuer;
            public DateTime? CertNotBefore;
            public DateTime? CertNotAfter;
        }

        // ===== Main =====
        public static async Task<HttpProbeResult> RunAsync(string url, CancellationToken ct)
        {
            var result = new HttpProbeResult
            {
                Url = url,
                FinalUrl = url,
                Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                RedirectChain = new List<string>(),
                ProbedAt = DateTime.UtcNow
            };

            Uri current;
            if (!Uri.TryCreate(url, UriKind.Absolute, out current))
            {
                result.Error = "Invalid URL";
                return result;
            }

            using (var total = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                total.CancelAfter(TotalTimeout);
                CancellationToken token = total.Token;

                try
                {
                    for (int hop = 0; hop <= MaxRedirects; hop++)
                    {
                        // Записываем до проверки, чтобы заблокированный шаг всё равно отображался в цепочке
                        result.RedirectChain.Add(current.AbsoluteUri);
                        result.FinalUrl = current.AbsoluteUri;

                        string blocked = PreCheckTarget(current);
                        if (blocked != null) { result.Error = blocked; return result; }

                        // 1) Разрешение DNS РОВНО ОДИН РАЗ
                        IPAddress[] ips;
                        try
                        {
                            ips = await ResolveAsync(GetNetworkHost(current), token).ConfigureAwait(false);
                        }
                        catch (SocketException)
                        {
                            result.Error = "Domain does not resolve";
                            return result;
                        }
                        if (ips.Length == 0)
                        {
                            result.Error = "Domain does not resolve";
                            return result;
                        }

                        // 2) Проверяем ВСЕ IP; достаточно одного непубличного IP для блокировки
                        foreach (IPAddress ip in ips)
                        {
                            if (!IsPublicAddress(ip))
                            {
                                result.Error = "Blocked: host resolves to a non-public address (" + ip + ")";
                                return result;
                            }
                        }

                        // 3) Подключаемся напрямую к только что проверенным IP (без повторного разрешения)
                        RawResponse resp = await ProbeOnceAsync(current, ips, token).ConfigureAwait(false);

                        result.StatusCode = resp.StatusCode;
                        result.ReasonPhrase = resp.ReasonPhrase;

                        string ctype;
                        result.ContentType = null;
                        result.RawContentType = null;
                        if (resp.Headers.TryGetValue("Content-Type", out ctype))
                        {
                            result.RawContentType = ctype;
                            int semi = ctype.IndexOf(';');
                            result.ContentType = (semi >= 0 ? ctype.Substring(0, semi) : ctype).Trim();
                        }

                        // Сохраняем этот шаг для отображения на экране Detail
                        string location;
                        resp.Headers.TryGetValue("Location", out location);
                        result.Hops.Add(new HttpHop
                        {
                            Url = current.AbsoluteUri,
                            Ips = string.Join(", ", ips.Select(x => x.ToString())),
                            StatusCode = resp.StatusCode,
                            ReasonPhrase = resp.ReasonPhrase,
                            Location = location,
                            TlsProtocol = resp.TlsProtocol,
                            CertSubject = resp.CertSubject,
                            CertIssuer = resp.CertIssuer,
                            CertNotBefore = resp.CertNotBefore,
                            CertNotAfter = resp.CertNotAfter
                        });

                        result.Headers.Clear();                       // сохраняем заголовки только последнего шага
                        foreach (var kv in resp.Headers)
                            result.Headers[kv.Key] = kv.Value;

                        if (resp.StatusCode >= 300 && resp.StatusCode < 400)
                        {
                            string loc;
                            if (resp.Headers.TryGetValue("Location", out loc) && !string.IsNullOrWhiteSpace(loc))
                            {
                                Uri next;
                                if (!Uri.TryCreate(current, loc.Trim(), out next))
                                {
                                    result.Error = "Invalid URL or redirect target";
                                    return result;
                                }
                                current = next;
                                continue;
                            }
                        }
                        return result;                                // перенаправлений больше нет
                    }
                    result.Error = "Too many redirects (max " + MaxRedirects + ")";
                }
                catch (OperationCanceledException)
                {
                    result.Error = ct.IsCancellationRequested ? "Cancelled" : "Timeout";
                }
                catch (Exception) when (token.IsCancellationRequested)
                {
                    // При отмене сокет закрывается, что приводит к ObjectDisposedException/IOException
                    result.Error = ct.IsCancellationRequested ? "Cancelled" : "Timeout";
                }
                catch (AuthenticationException ex)
                {
                    result.Error = "TLS failed: " + (ex.InnerException?.Message ?? ex.Message);
                }
                catch (IOException ex)
                {
                    result.Error = "Connection failed: " + (ex.InnerException?.Message ?? ex.Message);
                }
                catch (SocketException ex)
                {
                    result.Error = "Connection failed: " + ex.Message;
                }
                catch (UriFormatException)
                {
                    result.Error = "Invalid URL or redirect target";
                }
                catch (Exception ex)
                {
                    result.Error = ex.GetType().Name;
                }
            }

            return result;
        }

        // Ранняя проверка scheme и IP-литерала; основная блокировка — проверка IP после разрешения в RunAsync
        internal static string PreCheckTarget(Uri uri)
        {
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                return "Unsupported scheme: " + uri.Scheme;

            IPAddress literal;
            if (IPAddress.TryParse(uri.DnsSafeHost, out literal) && !IsPublicAddress(literal))
                return "Blocked: host is a non-public address (" + literal + ")";

            return null;
        }

        private static string GetNetworkHost(Uri uri)
        {
            return uri.HostNameType == UriHostNameType.Dns ? uri.IdnHost : uri.DnsSafeHost;
        }

        // Dns.GetHostAddressesAsync в .NET Framework не принимает CancellationToken
        private static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken token)
        {
            Task<IPAddress[]> dnsTask = Dns.GetHostAddressesAsync(host);
            Task cancelTask = Task.Delay(Timeout.Infinite, token);

            Task done = await Task.WhenAny(dnsTask, cancelTask).ConfigureAwait(false);
            if (done != dnsTask)
            {
                // Гасим ошибку dnsTask (если есть), чтобы не возникло "unobserved exception"
                var ignored = dnsTask.ContinueWith(t => { var e = t.Exception; },
                    TaskContinuationOptions.OnlyOnFaulted);
                token.ThrowIfCancellationRequested();
            }
            return await dnsTask.ConfigureAwait(false);
        }

        // ===== Открытие соединения к одному из проверенных IP =====
        private static async Task<TcpClient> ConnectAsync(IPAddress[] ips, int port, CancellationToken token)
        {
            Exception last = null;
            foreach (IPAddress ip in ips)
            {
                var tcp = new TcpClient(ip.AddressFamily) { NoDelay = true };
                try
                {
                    using (token.Register(() => tcp.Close()))
                    {
                        await tcp.ConnectAsync(ip, port).ConfigureAwait(false);
                    }
                    token.ThrowIfCancellationRequested();
                    return tcp;
                }
                catch (Exception ex)
                {
                    tcp.Close();
                    token.ThrowIfCancellationRequested();
                    last = ex;                                    // пробуем следующий IP
                }
            }
            throw new IOException("Could not connect to any address",
                last ?? new SocketException((int)SocketError.HostUnreachable));
        }

        // ===== Отправка GET-запроса и чтение заголовков =====
        private static async Task<RawResponse> ProbeOnceAsync(Uri uri, IPAddress[] ips, CancellationToken token)
        {
            using (TcpClient tcp = await ConnectAsync(ips, uri.Port, token).ConfigureAwait(false))
            using (token.Register(() => tcp.Close()))             // при отмене закрываем сокет
            {
                Stream stream = tcp.GetStream();
                SslStream tlsInfo = null;
                try
                {
                    if (uri.Scheme == Uri.UriSchemeHttps)
                    {
                        // TLS проверяет сертификат по ИСХОДНОМУ ДОМЕННОМУ ИМЕНИ, хотя сокет подключён к IP
                        var ssl = new SslStream(stream, false);
                        stream = ssl;
                        await ssl.AuthenticateAsClientAsync(
                            GetNetworkHost(uri), null, SslProtocols.None, false).ConfigureAwait(false);
                        tlsInfo = ssl;
                    }

                    byte[] request = BuildRequestBytes(uri);
                    await stream.WriteAsync(request, 0, request.Length, token).ConfigureAwait(false);
                    await stream.FlushAsync(token).ConfigureAwait(false);

                    string headerBlock = await ReadHeaderBlockAsync(stream, token).ConfigureAwait(false);
                    RawResponse parsed = ParseResponse(headerBlock);
                    FillTlsInfo(parsed, tlsInfo);
                    return parsed;
                }
                finally
                {
                    stream.Dispose();
                }
            }
        }

        // Сохраняет протокол TLS и сертификат сервера (если https)
        private static void FillTlsInfo(RawResponse resp, SslStream ssl)
        {
            if (ssl == null) return;

            resp.TlsProtocol = ssl.SslProtocol.ToString();
            try
            {
                if (ssl.RemoteCertificate != null)
                {
                    var cert = new X509Certificate2(ssl.RemoteCertificate);
                    resp.CertSubject = cert.Subject;
                    resp.CertIssuer = cert.Issuer;
                    resp.CertNotBefore = cert.NotBefore.ToUniversalTime();
                    resp.CertNotAfter = cert.NotAfter.ToUniversalTime();
                }
            }
            catch (Exception)
            {
                // если сертификат прочитать не удалось, пропускаем; остальные данные остаются доступны
            }
        }

        private static byte[] BuildRequestBytes(Uri uri)
        {
            string host = uri.HostNameType == UriHostNameType.IPv6
                ? "[" + uri.DnsSafeHost + "]"
                : GetNetworkHost(uri);
            if (!uri.IsDefaultPort) host += ":" + uri.Port;

            var sb = new StringBuilder();
            sb.Append("GET ").Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(host).Append("\r\n");
            sb.Append("User-Agent: ").Append(BrowserUserAgent).Append("\r\n");
            sb.Append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
            sb.Append("Accept-Language: en-US,en;q=0.9\r\n");
            sb.Append("Accept-Encoding: identity\r\n");           // без сжатия, тело мы всё равно не читаем
            sb.Append("Connection: close\r\n");
            sb.Append("\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        // Читает до \r\n\r\n, ограничение 64 КБ
        private static async Task<string> ReadHeaderBlockAsync(Stream stream, CancellationToken token)
        {
            var ms = new MemoryStream();
            var buf = new byte[4096];

            while (true)
            {
                int n = await stream.ReadAsync(buf, 0, buf.Length, token).ConfigureAwait(false);
                if (n == 0)
                    throw new IOException("Connection closed before headers were received");

                ms.Write(buf, 0, n);
                if (ms.Length > MaxHeaderBlockBytes)
                    throw new IOException("Response headers too large");

                byte[] data = ms.GetBuffer();
                int len = (int)ms.Length;
                for (int i = 3; i < len; i++)
                {
                    if (data[i - 3] == 13 && data[i - 2] == 10 && data[i - 1] == 13 && data[i] == 10)
                        return Encoding.GetEncoding("ISO-8859-1").GetString(data, 0, i - 3);
                }
            }
        }

        private static RawResponse ParseResponse(string headerBlock)
        {
            string[] lines = headerBlock.Split(new[] { "\r\n" }, StringSplitOptions.None);

            // Строка статуса: "HTTP/1.1 200 OK"
            string[] parts = lines[0].Split(new[] { ' ' }, 3);
            int code;
            if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)
                || !int.TryParse(parts[1], out code))
                throw new IOException("Invalid HTTP response");

            var resp = new RawResponse
            {
                StatusCode = code,
                ReasonPhrase = parts.Length == 3 ? parts[2] : string.Empty
            };

            for (int i = 1; i < lines.Length; i++)
            {
                int idx = lines[i].IndexOf(':');
                if (idx <= 0) continue;                           // пропускаем ошибочные или свёрнутые (folded) строки

                string name = lines[i].Substring(0, idx).Trim();
                string value = lines[i].Substring(idx + 1).Trim();

                string existing;
                if (resp.Headers.TryGetValue(name, out existing))
                    value = existing + ", " + value;              // повторяющийся заголовок объединяем через ", "

                resp.Headers[name] = Limit(value);
            }
            return resp;
        }

        // ===== Является ли IP публичным адресом =====
        internal static bool IsPublicAddress(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // ::ffff:a.b.c.d -> проверяем как IPv4
                bool mapped = true;
                for (int i = 0; i < 10; i++) if (b[i] != 0) { mapped = false; break; }
                if (mapped && b[10] == 0xFF && b[11] == 0xFF)
                    return IsPublicAddress(new IPAddress(new[] { b[12], b[13], b[14], b[15] }));

                if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6Any)) return false;
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
                if ((b[0] & 0xFE) == 0xFC) return false;                      // fc00::/7

                // ::/96 (IPv4-compatible, устаревший)
                bool first12Zero = true;
                for (int i = 0; i < 12; i++) if (b[i] != 0) { first12Zero = false; break; }
                if (first12Zero) return false;

                // 64:ff9b::/96 (NAT64): проверяем встроенный IPv4 в последних 4 байтах
                if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B)
                {
                    bool nat64 = true;
                    for (int i = 4; i < 12; i++) if (b[i] != 0) { nat64 = false; break; }
                    if (nat64)
                        return IsPublicAddress(new IPAddress(new[] { b[12], b[13], b[14], b[15] }));
                }

                // 2002::/16 (6to4): IPv4 встроен в байты 2..5
                if (b[0] == 0x20 && b[1] == 0x02)
                    return IsPublicAddress(new IPAddress(new[] { b[2], b[3], b[4], b[5] }));

                // 2001::/32 (Teredo) и 2001:db8::/32 (документация)
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) return false;
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false;

                return true;
            }

            if (b[0] == 0 || b[0] == 10 || b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;                       // link-local, метаданные облака
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;        // CGNAT
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;       // benchmark
            if (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) return false;   // 192.0.0.0/24, 192.0.2.0/24
            if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;        // 198.51.100.0/24
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;         // 203.0.113.0/24
            if (b[0] >= 224) return false;                                      // multicast + reserved
            return true;
        }

        private static string Limit(string v)
        {
            return v.Length > MaxHeaderValueLength ? v.Substring(0, MaxHeaderValueLength) : v;
        }
    }
}