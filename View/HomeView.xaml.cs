using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Activation;
using System.Threading;                         // [НОВОЕ] для CancellationTokenSource
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
    // Одна строка "метка: значение" в разделе деталей пункта проверки.
    // Value == null — строка является заголовком группы (например "Flagged as malicious (3)").
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
        private string _finding, _level, _assessment;
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

        // Собственная оценка этого пункта (если есть), отображается в блоке ASSESSMENT экрана Detail.
        // Если пусто, Detail использует общую рекомендацию по Level.
        public string Assessment
        {
            get { return _assessment; }
            set { _assessment = value; OnPropertyChanged(); }
        }

        // Подробное содержимое (что удалось загрузить и проверить) для экрана Detail.
        // При новом результате список присваивается целиком, чтобы DetailView обновился автоматически.
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
        private API_request _api;     // создаётся лениво, при первой проверке
        private int _checkId;         // нумерация каждой проверки, чтобы отбрасывать устаревшие результаты

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

        private bool _checking;   // идёт ожидание проверки сети

        private CancellationTokenSource _netCts;   // [НОВОЕ] для защиты от дребезга (debounce)
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

            // Отменяем предыдущее сканирование, если оно ещё выполняется
            _scanCts?.Cancel();
            _scanCts = null;

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
                redirects = new CheckItem
                {
                    Criterion = "Redirects",
                    Finding = "Scanning...",
                    Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for the server to answer...")
                };
                reputation = new CheckItem
                {
                    Criterion = "Reputation",
                    Finding = "Scanning...",
                    Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for VirusTotal to finish the scan...")
                };
                contentType = new CheckItem
                {
                    Criterion = "Content-Type",
                    Finding = "Scanning...",
                    Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for the server to answer...")
                };
                blacklist = new CheckItem
                {
                    Criterion = "Blacklist",
                    Finding = "Scanning...",
                    Level = "Warning",
                    Details = CheckDetails.Pending("Waiting for VirusTotal to finish the scan...")
                };
                items.Add(redirects);
                items.Add(reputation);
                items.Add(contentType);
                items.Add(blacklist);
            }

            // 3) Показываем результаты Offline Check
            _lastUrl = input;
            _lastItems = items;
            ShowResult(items, input);

            // 4) ПРОВЕРКА DANGER: ОСТАНАВЛИВАЕМ ВЕСЬ ПРОЦЕСС
            bool offlineDanger = items.Any(i => i.Level == "Danger");

            if (offlineDanger)
            {
                StatusText.Text = "Blocked: Offline Check detected a dangerous URL.";

                // Не запускаем VirusTotal
                // Не запускаем HTTP Online Check
                // Не создаём новых сетевых задач
                return;
            }

            // 5) Продолжаем Online Check, только если Offline Check не нашёл Danger
            StatusText.Text = "Checked: " + uri.Host +
                              (OnlineMode ? " - scanning online..." : " (offline)");

            if (!OnlineMode) return;

            // Отменяем предыдущее сканирование, если оно ещё выполняется
            _scanCts?.Cancel();

            // Создаём отдельный токен для текущего сканирования
            var scanCts = new CancellationTokenSource();
            _scanCts = scanCts;

            bool[] ok;
            try
            {
                // VirusTotal (медленно, может занимать более минуты) и HTTP-проверка выполняются параллельно:
                // что завершилось раньше — заполняется раньше, ошибка одного не уничтожает результат другого
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

            if (myId != _checkId) return;   // пользователь нажал Clear или проверил другую ссылку

            StatusText.Text = ok.All(x => x)
                ? "Checked: " + uri.Host
                : "Checked: " + uri.Host + " (some online checks failed)";
            UpdateVerdict(items);
        }

        // Сканирует VirusTotal и заполняет строки Reputation и Blacklist. Возвращает false при ошибке.
        //  - HomeView получает общий вывод: Finding + Level (из VtVerdict).
        //  - DetailView получает Assessment и Details (из VtReport / VtVerdict).
        private async Task<bool> FillVirusTotalAsync(string url, int myId, CheckItem reputation, CheckItem blacklist)
        {
            try
            {
                ScanResult r = await GetApi().ScanUrlAsync(url);

                if (myId != _checkId) return true;   // устаревший результат, отбрасываем

                // Исходный JSON уже сохранён API_request в RAM: разбираем детально через VT_response
                VtReport report = null;
                VtVerdict verdict = null;
                try
                {
                    string rawJson = VT_ScanStore.Load(r.AnalysisId);
                    if (!string.IsNullOrWhiteSpace(rawJson))
                    {
                        report = VtReport.Parse(r.AnalysisId, rawJson);
                        verdict = VtVerdictBuilder.Build(report);
                    }
                }
                catch (Exception parseEx)
                {
                    System.Diagnostics.Debug.WriteLine("VT_response error: " + parseEx.Message);
                    report = null;
                    verdict = null;
                }

                if (verdict != null)
                {
                    // Blacklist: общий вывод берётся из verdict, чтобы Home и Detail всегда совпадали
                    blacklist.Finding = verdict.Finding;
                    blacklist.Level = CardLevel(verdict.Level);
                    blacklist.Assessment = verdict.Assessment;
                    blacklist.Details = CheckDetails.ForBlacklist(report, verdict);

                    // Reputation: если есть срабатывания движков или охват слишком низкий (verdict Unknown), не сообщаем Safe
                    reputation.Finding = report.Harmless + " harmless, " + report.Undetected + " undetected";
                    reputation.Level = (report.Malicious + report.Suspicious) > 0 || verdict.Level == "Unknown"
                        ? "Warning" : "Safe";
                    reputation.Assessment = verdict.Level == "Unknown" ? verdict.Assessment : null;
                    reputation.Details = CheckDetails.ForReputation(report);
                }
                else
                {
                    // Нет исходного JSON или он не читается: используем сводные данные из API_request
                    int total = r.Malicious + r.Suspicious + r.Harmless + r.Undetected;

                    blacklist.Finding = r.Malicious + " malicious, " + r.Suspicious + " suspicious (of " + total + " engines)";
                    blacklist.Level = r.Malicious > 0 ? "Danger" : r.Suspicious > 0 ? "Warning" : "Safe";
                    blacklist.Details = CheckDetails.ForBlacklist(r);

                    reputation.Finding = r.Harmless + " harmless, " + r.Undetected + " undetected";
                    reputation.Level = (r.Malicious + r.Suspicious) > 0 ? "Warning" : "Safe";
                    reputation.Details = CheckDetails.ForReputation(r);
                }

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

        // В интерфейсе только 3 уровня Safe / Warning / Danger; "Unknown" вердикта показывается как Warning
        private static string CardLevel(string level)
        {
            return (level == "Safe" || level == "Danger") ? level : "Warning";
        }

        // HTTP-проверка (без загрузки тела) и заполнение строк Redirects и Content-Type. Возвращает false при ошибке.
        private async Task<bool> FillHttpAsync(string url, int myId, CancellationToken token,
                                               CheckItem redirects, CheckItem contentType)
        {
            try
            {
                HttpProbeResult p = await ClientMng.RunAsync(url, token);

                if (myId != _checkId) return true;   // устаревший результат, отбрасываем

                // Redirects: сохраняем прежнее отображение (код статуса). Если корректный ответ
                // не получен, сообщаем об ошибке вместо "0 / Safe".
                if (p.Error != null)
                {
                    redirects.Finding = p.Error;
                    redirects.Level = "Warning";
                }
                else
                {
                    redirects.Finding = $"{(int)p.StatusCode} - {p.ReasonPhrase}";
                    redirects.Level = CheckDetails.RedirectsLevel(p);
                }
                redirects.Details = CheckDetails.ForRedirects(p);

                // Content-Type (заменяет прежнюю строку SSL)
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

        // Собирает отображение и вердикт для повторного вызова после получения онлайн-результатов
        private void ShowResult(List<CheckItem> items, string input)
        {
            ResultGrid.ItemsSource = items;
            CheckedUrlText.Text = input;
            UpdateVerdict(items);

            // Есть результат: скрываем заголовок, чтобы таблица результатов занимала почти весь экран,
            // поле ввода URL остаётся сверху и прокручивается вместе со страницей при прокрутке колесом.
            HeroText.Visibility = Visibility.Collapsed;
            EmptyHint.Visibility = Visibility.Collapsed;
            PipelineOverview.Visibility = Visibility.Collapsed;
            ResultPanel.Visibility = Visibility.Visible;
            PageScroll.ScrollToTop();
        }

        // DataGrid перехватывает событие прокрутки колесом; передаём его ScrollViewer всей страницы
        private void ResultGrid_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            PageScroll.ScrollToVerticalOffset(PageScroll.VerticalOffset - e.Delta * 0.8);
            e.Handled = true;
        }

        // Каждый шаг содержит свои критерии (Criterion)
        private static readonly string[][] StepCriteria =
{
    new[] { "Protocol", "Domain", "Punycode (IDN)", "Mixed writing systems", "Brand impersonation", "IP address" }, // Offline
    new[] { "Redirects", "Content-Type" },                                                               // Online (HTTP)
    new[] { "Reputation", "Blacklist" }                                                                  // VirusTotal
};

        private static Brush Hex(string hex)
        {
            return (Brush)new BrushConverter().ConvertFromString(hex);
        }

        private void UpdateVerdict(List<CheckItem> items)
        {
            TextBlock[] labels = { StepOfflineText, StepOnlineText, StepVtText };
            bool anyDanger = items.Any(i => i.Level == "Danger");
            int warnSteps = 0;
            bool pending = false;

            for (int s = 0; s < StepCriteria.Length; s++)
            {
                List<CheckItem> step = items.Where(i => StepCriteria[s].Contains(i.Criterion)).ToList();

                if (step.Count == 0)                                  // офлайн-режим: шаг не выполняется
                {
                    labels[s].Text = "Not run";
                    labels[s].Foreground = Hex("#668BA4");
                    continue;
                }

                if (step.Any(i => i.Finding == "Scanning..."))
                {
                    pending = true;
                    labels[s].Text = "Scanning...";
                    labels[s].Foreground = Hex("#82A8C0");
                    continue;
                }

                int warn = step.Count(i => i.Level == "Warning");
                bool stepWarn = warn * 2 >= step.Count;               // warning >= 50% критериев
                if (stepWarn) warnSteps++;

                string status = step.Any(i => i.Level == "Danger") ? "Danger"
                              : stepWarn ? "Warning" : "Safe";

                labels[s].Text = status + "  (" + warn + "/" + step.Count + " warning)";
                labels[s].Foreground = status == "Danger" ? Hex("#FF6B7A")
                                     : status == "Warning" ? Hex("#F2C14E")
                                     : Hex("#5FD99B");
            }

            if (anyDanger || warnSteps >= 2)
            {
                VerdictText.Text = "DANGEROUS";
                VerdictText.Foreground = Hex("#FF6B7A");
            }
            else if (pending)
            {
                VerdictText.Text = "CHECKING...";
                VerdictText.Foreground = Hex("#82A8C0");
            }
            else if (warnSteps == 1)
            {
                VerdictText.Text = "WARNING";
                VerdictText.Foreground = Hex("#F2C14E");
            }
            else
            {
                VerdictText.Text = "SAFE";
                VerdictText.Foreground = Hex("#5FD99B");
            }
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
        // Экспорт всех результатов (все карточки в открытом состоянии) в HTML-файл
        private void Export_Click(object sender, RoutedEventArgs e)
        {
            ExportCommand.Run(_lastUrl, _lastItems, msg => StatusText.Text = msg);
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