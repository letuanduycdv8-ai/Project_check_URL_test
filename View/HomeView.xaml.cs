using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Activation;
using System.Threading;                         // [MỚI] cho CancellationTokenSource
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Net.NetworkInformation;
using System.ComponentModel;
using System.Runtime.CompilerServices;
namespace Project_check_URL.View
{
    public class DetailRequestedEventArgs : EventArgs
    {
        public string Url { get; set; }
        public List<CheckItem> Items { get; set; }
    }
    // Một dòng "nhãn: giá trị" trong phần chi tiết của một mục kiểm tra.
    // Value == null thì dòng này là tiêu đề nhóm (vd "Flagged as malicious (3)").
    public class DetailLine
    {
        public DetailLine(string label, string value)
        {
            Label = label;
            Value = value;
        }

        public string Label { get; }
        public string Value { get; }
        public bool IsHeading { get { return Value == null; } }
    }

    public class CheckItem : INotifyPropertyChanged
    {
        private string _finding, _level;
        private List<DetailLine> _details = new List<DetailLine>();

        public string Criterion { get; set; }

        public string Finding
        {
            get { return _finding; }
            set { _finding = value; OnPropertyChanged(); }
        }

        public string Level
        {
            get { return _level; }
            set { _level = value; OnPropertyChanged(); }
        }

        // Nội dung chi tiết (những gì đã tải và kiểm tra được) cho màn hình Detail.
        // Gán lại cả danh sách khi có kết quả mới để DetailView tự cập nhật.
        public List<DetailLine> Details
        {
            get { return _details; }
            set { _details = value ?? new List<DetailLine>(); OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }


    public partial class HomeView : UserControl
    {
        private API_request _api;     // tạo lười, lần quét đầu tiên
        private int _checkId;         // đánh số mỗi lần kiểm tra, để bỏ kết quả cũ

        private API_request GetApi()
        {
            if (_api == null)
            {
                string key = "326f31e0c1cd810509de12b95c48924202583fc52178dd26ce7e475d442fda9c";
                _api = new API_request(key);
            }
            return _api;
        }
        public event EventHandler<DetailRequestedEventArgs> DetailRequested;

        private string _lastUrl;
        private List<CheckItem> _lastItems;

        private bool _checking;   // đang đợi kiểm tra mạng

        private CancellationTokenSource _netCts;   // [MỚI] dùng để chống rung (debounce)
        private CancellationTokenSource _scanCts;

        // True when the switch is ON (online checks allowed)
        private bool OnlineMode => OnlineToggle.IsChecked == true;

        public HomeView()
        {
            InitializeComponent();

            string path = System.IO.Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory, "Data", "confusables.txt");
            Offline_check.LoadConfusables(path);

            Loaded += (s, e) =>
            {
                NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
                NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            };
            Unloaded += (s, e) =>
            {
                NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
                NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
                _netCts?.Cancel();
            };

            _ = RefreshNetworkAsync();
        }

        private void SetChecking(bool busy)
        {
            _checking = busy;
            CheckingSpinner.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
            OnlineToggle.IsEnabled = !busy;
            if (busy)
            {
                OnlineToggle.Content = "Checking...";
                StatusText.Text = "Checking connection...";
            }
        }

        //
        private async Task RefreshNetworkAsync()
        {
            if (_checking) return;
            SetChecking(true);

            bool online = false;
            try
            {
                online = await Check_Internet.IsOnlineAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Error: " + ex);
            }
            finally
            {
                SetChecking(false);
            }

            OnlineToggle.IsChecked = online;
            ApplyNetworkState();
            StatusText.Text = "Ready";
        }


        private void OnNetworkChanged(object sender, NetworkAvailabilityEventArgs e)
            => _ = DebouncedRefreshAsync();

        private void OnNetworkAddressChanged(object sender, EventArgs e)
            => _ = DebouncedRefreshAsync();
        private async Task DebouncedRefreshAsync()
        {
            _netCts?.Cancel();
            _netCts = new CancellationTokenSource();
            var token = _netCts.Token;

            try
            {
                await Task.Delay(1500, token);
                await Dispatcher.InvokeAsync(() => RefreshNetworkAsync()).Task.Unwrap();
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Network refresh: " + ex.Message);
            }
        }

        private void ApplyNetworkState()
        {
            bool on = OnlineMode;
            OnlineToggle.Content = on ? "Online" : "Offline";
            OnlineCard.Opacity = on ? 1.0 : 0.45;
            Onl_history.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        }
        private void OnlineToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (OnlineCard == null || Onl_history == null
                || OnlineToggle == null || _checking) return;

            ApplyNetworkState();
        }

        private async void CheckButton_Click(object sender, RoutedEventArgs e)
        {
            if (_checking)
            {
                StatusText.Text = "Checking connection, please wait...";
                return;
            }

            string input = LinkTextBox.Text.Trim();
            if (!Uri.TryCreate(input, UriKind.Absolute, out Uri uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                MessageBox.Show("Please enter a valid URL, example: https://example.com");
                return;
            }

            int myId = ++_checkId;
            // Offline check
            List<CheckFinding> homograph = Offline_check.CheckHomograph(uri);
            string domainLevel = homograph.Any(f => f.Level == "Danger") ? "Danger" :
                                 homograph.Any(f => f.Level == "Warning") ? "Warning" :
                                 "Safe";

            var items = new List<CheckItem>
    {
        new CheckItem { Criterion = "Protocol",
            Finding = uri.Scheme == "https" ? "HTTPS (encrypted)" : "HTTP (not encrypted)",
            Level = uri.Scheme == "https" ? "Safe" : "Warning",
            Details = CheckDetails.ForProtocol(uri) },
        new CheckItem { Criterion = "Domain",
            Finding = uri.Host, Level = domainLevel,
            Details = CheckDetails.ForDomain(uri) },
    };

            foreach (CheckFinding f in homograph)
            {
                items.Add(new CheckItem
                {
                    Criterion = f.Criterion,
                    Finding = f.Finding,
                    Level = f.Level,
                    Details = CheckDetails.ForHomograph(uri, f)
                });
            }

            // OnlineCheck
            CheckItem redirects = null, reputation = null, contentType = null, blacklist = null;
            if (OnlineMode)
            {
                redirects = new CheckItem { Criterion = "Redirects", Finding = "Scanning...", Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for the server to answer...") };
                reputation = new CheckItem { Criterion = "Reputation", Finding = "Scanning...", Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for VirusTotal to finish the scan...") };
                contentType = new CheckItem { Criterion = "Content-Type", Finding = "Scanning...", Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for the server to answer...") };
                blacklist = new CheckItem { Criterion = "Blacklist", Finding = "Scanning...", Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for VirusTotal to finish the scan...") };
                items.Add(redirects);
                items.Add(reputation);
                items.Add(contentType);
                items.Add(blacklist);
            }

            // 3) Hiển thị ngay kết quả offline
            _lastUrl = input;
            _lastItems = items;
            ShowResult(items, input);
            StatusText.Text = "Checked: " + uri.Host + (OnlineMode ? " - scanning online..." : " (offline)");

            if (!OnlineMode) return;

            // Hủy lần quét trước nếu vẫn đang chạy
            _scanCts?.Cancel();

            // Tạo token riêng cho lần quét hiện tại
            var scanCts = new CancellationTokenSource();
            _scanCts = scanCts;

            bool[] ok;
            try
            {
                // VirusTotal (chậm, có thể hơn 1 phút) và thăm dò HTTP chạy song song:
                // cái nào xong trước thì điền trước, cái này lỗi không làm mất kết quả cái kia
                ok = await Task.WhenAll(
                    FillVirusTotalAsync(input, myId, reputation, blacklist),
                    FillHttpAsync(input, myId, scanCts.Token, redirects, contentType));
            }
            finally
            {
                if (ReferenceEquals(_scanCts, scanCts))
                    _scanCts = null;

                scanCts.Dispose();
            }

            if (myId != _checkId) return;   // người dùng đã Clear hoặc kiểm tra link khác

            StatusText.Text = ok.All(x => x)
                ? "Checked: " + uri.Host
                : "Checked: " + uri.Host + " (some online checks failed)";
            UpdateVerdict(items);
        }

        // Quét VirusTotal rồi điền vào hàng Reputation và Blacklist. Trả về false nếu lỗi.
        private async Task<bool> FillVirusTotalAsync(string url, int myId, CheckItem reputation, CheckItem blacklist)
        {
            try
            {
                ScanResult r = await GetApi().ScanUrlAsync(url);

                if (myId != _checkId) return true;   // kết quả cũ, bỏ

                int total = r.Malicious + r.Suspicious + r.Harmless + r.Undetected;

                blacklist.Finding = r.Malicious + " malicious, " + r.Suspicious + " suspicious (of " + total + " engines)";
                blacklist.Level = r.Malicious > 0 ? "Danger" : r.Suspicious > 0 ? "Warning" : "Safe";
                blacklist.Details = CheckDetails.ForBlacklist(r);

                reputation.Finding = r.Harmless + " harmless, " + r.Undetected + " undetected";
                reputation.Level = (r.Malicious + r.Suspicious) > 0 ? "Warning" : "Safe";
                reputation.Details = CheckDetails.ForReputation(r);
                return true;
            }
            catch (Exception ex)
            {
                if (myId != _checkId) return false;

                blacklist.Finding = "Unavailable: " + ex.Message;
                blacklist.Details = CheckDetails.ForError("VirusTotal", ex);
                reputation.Finding = "Unavailable";
                reputation.Details = CheckDetails.ForError("VirusTotal", ex);
                return false;
            }
        }

        // Thăm dò HTTP (không tải body) rồi điền vào hàng Redirects và Content-Type. Trả về false nếu lỗi.
        private async Task<bool> FillHttpAsync(string url, int myId, CancellationToken token,
                                               CheckItem redirects, CheckItem contentType)
        {
            try
            {
                HttpProbeResult p = await ClientMng.RunAsync(url, token);

                if (myId != _checkId) return true;   // kết quả cũ, bỏ

                // Redirects: giữ cách hiển thị cũ (mã trạng thái). Nếu không nhận được phản hồi
                // hợp lệ thì báo lỗi thay vì hiện "0 / Safe".
                if (p.Error != null)
                {
                    redirects.Finding = p.Error;
                    redirects.Level = "Warning";
                }
                else
                {
                    redirects.Finding = p.StatusCode.ToString();
                    redirects.Level = (300 < p.StatusCode && p.StatusCode < 400) ? "Warning" : "Safe";
                }
                redirects.Details = CheckDetails.ForRedirects(p);

                // Content-Type (thay cho hàng SSL cũ)
                if (p.ContentType == null)
                {
                    contentType.Finding = p.Error != null ? "Unavailable: " + p.Error : "Not provided";
                    contentType.Level = "Warning";
                }
                else
                {
                    contentType.Finding = p.ContentType;
                    contentType.Level = CheckDetails.ContentTypeLevel(p);
                }
                contentType.Details = CheckDetails.ForContentType(p);

                return p.Error == null;
            }
            catch (Exception ex)
            {
                if (myId != _checkId) return false;

                redirects.Finding = "Unavailable: " + ex.Message;
                redirects.Details = CheckDetails.ForError("HTTP check", ex);
                contentType.Finding = "Unavailable";
                contentType.Details = CheckDetails.ForError("HTTP check", ex);
                return false;
            }
        }

        // Gom phần hiển thị + verdict để gọi lại sau khi có kết quả online
        private void ShowResult(List<CheckItem> items, string input)
        {
            ResultGrid.ItemsSource = items;
            CheckedUrlText.Text = input;
            UpdateVerdict(items);

            // Có kết quả: ẩn phần tiêu đề để bảng kết quả chiếm gần hết màn hình,
            // ô nhập URL nằm gọn phía trên và sẽ cuộn lên cùng trang khi lăn chuột.
            HeroText.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Collapsed;
            PipelineOverview.Visibility = Visibility.Collapsed;
            ResultPanel.Visibility = Visibility.Visible;
            PageScroll.ScrollToTop();
        }

        // DataGrid nuốt sự kiện lăn chuột; chuyển nó cho ScrollViewer của cả trang
        private void ResultGrid_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            PageScroll.ScrollToVerticalOffset(PageScroll.VerticalOffset - e.Delta * 0.8);
            e.Handled = true;
        }
        private void UpdateVerdict(List<CheckItem> items)
        {
            if (items.Any(i => i.Level == "Danger"))
            {
                VerdictText.Text = "DANGEROUS";
                VerdictText.Foreground = Brushes.Red;
            }
            else
            {
                VerdictText.Text = "SAMPLE RESULT";
                VerdictText.Foreground = Brushes.DarkOrange;
            }
            ScoreText.Text = "--";
        }
        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            LinkTextBox.Clear();
            ResultGrid.ItemsSource = null;
            ResultPanel.Visibility = Visibility.Collapsed;
            PipelineOverview.Visibility = Visibility.Visible;
            HeroText.Visibility = Visibility.Visible;
            EmptyHint.Visibility = Visibility.Visible;
            PageScroll.ScrollToTop();
            StatusText.Text = "Ready";
            _checkId++;
            _lastItems = null;
            _lastUrl = null;
            _scanCts?.Cancel();
            _scanCts = null;
        }
        private void Show_result(object sender, RoutedEventArgs e)
        {

            if (_lastItems == null) return;

            DetailRequested?.Invoke(this, new DetailRequestedEventArgs
            {
                Url = _lastUrl,
                Items = _lastItems
            });

        }
        private void Show_information(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Hello");
        }
        private void Tool_Enter(object sender, MouseEventArgs e)
        {
            var item = sender as FrameworkElement;
            StatusText.Text = item.Tag.ToString();
        }
        private void Leave(object sender, MouseEventArgs e)
        {
            StatusText.Text = "ready";
        }
    }
}