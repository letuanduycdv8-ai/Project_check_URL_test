using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace Project_check_URL.View
{
    // ------------------------------------------------------------------
    // Одна строка проверки на странице деталей. Оборачивает CheckItem со страницы Home,
    // поэтому при поступлении онлайн-результата (изменение Finding/Level) карточка обновляется сама.
    // ------------------------------------------------------------------
    public class DetailEntry : INotifyPropertyChanged
    {
        private readonly CheckItem _item;
        private bool _isSelected;
        private bool _isDimmed;

        public event PropertyChangedEventHandler PropertyChanged;
        public event EventHandler ItemChanged;

        public DetailEntry(CheckItem item)
        {
            _item = item;
            _item.PropertyChanged += Item_PropertyChanged;
        }

        public void Detach()
        {
            _item.PropertyChanged -= Item_PropertyChanged;
        }

        public string Criterion
        {
            get { return _item.Criterion; }
        }

        public string Finding
        {
            get
            {
                return string.IsNullOrWhiteSpace(_item.Finding)
                    ? "No details reported."
                    : _item.Finding;
            }
        }

        public string Level
        {
            get
            {
                string l = _item.Level;
                return (l == "Safe" || l == "Danger") ? l : "Warning";
            }
        }

        // Что удалось загрузить и проверить для этого пункта (показывается при нажатии на карточку)
        public List<DetailLine> Details
        {
            get { return _item.Details; }
        }

        public bool HasDetails
        {
            get { return _item.Details != null && _item.Details.Count > 0; }
        }

        public string About
        {
            get { return DetailView.AboutFor(Criterion); }
        }

        // Собственная оценка этого пункта (например, вердикт VirusTotal), если есть,
        // иначе общая рекомендация по уровню
        public string Advice
        {
            get
            {
                string own = _item.Assessment;
                return string.IsNullOrWhiteSpace(own) ? DetailView.AdviceFor(Level) : own;
            }
        }

        // карточка выбрана (развёрнута, выдвинута вперёд)
        public bool IsSelected
        {
            get { return _isSelected; }
            set { if (_isSelected != value) { _isSelected = value; Raise(); } }
        }

        // выбрана другая карточка: эта затемняется
        public bool IsDimmed
        {
            get { return _isDimmed; }
            set { if (_isDimmed != value) { _isDimmed = value; Raise(); } }
        }

        private void Item_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            Raise("Finding");
            Raise("Level");
            Raise("Advice");
            Raise("Details");
            Raise("HasDetails");
            ItemChanged?.Invoke(this, EventArgs.Empty);
        }

        private void Raise([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    // ------------------------------------------------------------------
    // Группа проверок (Static / VirusTotal / HTML)
    // ------------------------------------------------------------------
    public class DetailSection : INotifyPropertyChanged
    {
        private string _summary = "";
        private string _level = "None";

        public event PropertyChangedEventHandler PropertyChanged;

        public DetailSection(string number, string title, string subtitle, string emptyText)
        {
            Number = number;
            Title = title;
            Subtitle = subtitle;
            EmptyText = emptyText;
            Entries = new List<DetailEntry>();
        }

        public string Number { get; private set; }
        public string Title { get; private set; }
        public string Subtitle { get; private set; }
        public string EmptyText { get; private set; }
        public List<DetailEntry> Entries { get; private set; }

        public bool IsEmpty
        {
            get { return Entries.Count == 0; }
        }

        public string Summary
        {
            get { return _summary; }
            private set { if (_summary != value) { _summary = value; Raise(); } }
        }

        // худший уровень в группе: Safe / Warning / Danger / None (группа пуста)
        public string Level
        {
            get { return _level; }
            private set { if (_level != value) { _level = value; Raise(); } }
        }

        public void Refresh()
        {
            if (Entries.Count == 0)
            {
                Summary = "N/A";
                Level = "None";
                return;
            }

            int danger = Entries.Count(x => x.Level == "Danger");
            int warn = Entries.Count(x => x.Level == "Warning");
            int safe = Entries.Count(x => x.Level == "Safe");

            var parts = new List<string>();
            if (danger > 0) parts.Add(danger + " Danger");
            if (warn > 0) parts.Add(warn + " Warning");
            if (safe > 0) parts.Add(safe + " Safe");

            Summary = string.Join("  ·  ", parts);
            Level = danger > 0 ? "Danger" : warn > 0 ? "Warning" : "Safe";
        }

        private void Raise([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public partial class DetailView : UserControl
    {
        public event EventHandler BackRequested;

        private readonly List<DetailEntry> _all = new List<DetailEntry>();
        private readonly List<DetailSection> _sections;
        private readonly string _url;
        private readonly List<CheckItem> _items;

        public DetailView(string url, IEnumerable<CheckItem> items)
        {
            InitializeComponent();
            UrlText.Text = url;
            _url = url;
            _items = (items ?? Enumerable.Empty<CheckItem>()).ToList();

            const string offlineNote =
                "Not available in offline mode. Turn on Online mode and check the link again.";

            _sections = new List<DetailSection>
            {
                new DetailSection("1", "STATIC CHECK",
                    "Offline analysis of the link and its domain name",
                    "No static results."),
                new DetailSection("2", "VIRUSTOTAL RESULT",
                    "How the security engines on VirusTotal rate this URL",
                    offlineNote),
                new DetailSection("3", "HTML ANALYSIS",
                    "What the web server answers: status, redirects, content type and the start of the page",
                    offlineNote)
            };

            foreach (CheckItem item in _items)
            {
                var entry = new DetailEntry(item);
                entry.ItemChanged += (s, e) => RefreshSummaries();
                _all.Add(entry);
                _sections[GroupOf(item.Criterion)].Entries.Add(entry);
            }

            SectionList.ItemsSource = _sections;
            RefreshSummaries();

            // не позволяем CheckItem (живущему на странице Home) держать ссылку на закрытую страницу
            Unloaded += (s, e) =>
            {
                foreach (DetailEntry en in _all) en.Detach();
            };
        }

        // 0 = static, 1 = VirusTotal, 2 = HTML/HTTP. Неизвестные пункты по умолчанию попадают в "static".
        internal static int GroupOf(string criterion)
        {
            switch (criterion)
            {
                case "Reputation":
                case "Blacklist":
                    return 1;
                case "Redirects":
                case "Content-Type":
                    return 2;
                default:
                    return 0;
            }
        }

        internal static string AboutFor(string criterion)
        {
            switch (criterion)
            {
                case "Protocol":
                    return "Checks whether the link uses HTTPS. HTTPS encrypts the traffic between you and the site; plain HTTP can be read or changed on the way.";
                case "Domain":
                    return "Reads the host name of the link. The domain checks below (punycode, mixed scripts, brand look-alikes) are all run on this name. In online mode it also looks up when the domain was registered (RDAP); a domain registered in the last 30 days raises a warning.";
                case "Punycode (IDN)":
                    return "Detects internationalized domain names (labels starting with xn--). Attackers register such names to build addresses that look like well-known sites.";
                case "Mixed writing systems":
                    return "Looks for domain labels that mix scripts, for example Latin and Cyrillic letters. This is a common trick to fake a trusted name.";
                case "Brand impersonation":
                    return "Compares the domain with a list of well-known brands, using Unicode look-alike characters and one-character typos (typosquatting).";
                case "Reputation":
                    return "Shows the VirusTotal community reputation score and votes, how third-party services categorise this URL, and when VirusTotal first saw it. A clean reputation lowers risk but does not prove safety. The engine counts are in Blacklist.";
                case "Blacklist":
                    return "Counts the VirusTotal engines that flagged this URL as malicious or suspicious. Any malicious verdict is treated as a strong warning sign. A VirusTotal report less than 24 hours old is reused instead of starting a new scan.";
                case "Redirects":
                    return "Contacts the server and follows redirects (up to 5). It raises a warning when the link ends on a different site, drops from HTTPS to HTTP, passes through many redirects, or a server uses an outdated TLS version, and it runs the look-alike checks again on every redirect target. Each step lists the resolved IP and, for https, the TLS protocol and certificate.";
                case "Content-Type":
                    return "Reads the Content-Type header, which tells what kind of file the link returns, and the file name offered for download. For an HTML page it also reads the first part as plain text (forms, password fields, hidden frames, automatic redirects). Nothing is run. A link that returns an installer, an executable or a forced download is a common way to deliver malware.";
                default:
                    return "Additional check performed on this link.";
            }
        }

        internal static string AdviceFor(string level)
        {
            switch (level)
            {
                case "Danger":
                    return "High risk. Do not open this link or enter any information. If it came from a message or an email, report it.";
                case "Warning":
                    return "Be careful. Verify where the link came from before you sign in or share personal data.";
                default:
                    return "No problem found for this check.";
            }
        }

        private void RefreshSummaries()
        {
            foreach (DetailSection s in _sections) s.Refresh();

            SafeCount.Text = _all.Count(x => x.Level == "Safe") + " Safe";
            WarnCount.Text = _all.Count(x => x.Level == "Warning") + " Warning";
            DangerCount.Text = _all.Count(x => x.Level == "Danger") + " Danger";
        }

        // Нажатие на карточку: она выдвигается вперёд и раскрывает содержимое, остальные затемняются.
        // Повторное нажатие на открытую карточку закрывает её, все карточки возвращаются в норму.
        private void Entry_Click(object sender, MouseButtonEventArgs e)
        {
            var header = sender as FrameworkElement;
            var entry = header == null ? null : header.DataContext as DetailEntry;
            if (entry == null) return;

            bool select = !entry.IsSelected;

            foreach (DetailEntry x in _all)
            {
                x.IsSelected = false;
                x.IsDimmed = select;
            }
            if (select)
            {
                entry.IsSelected = true;
                entry.IsDimmed = false;
            }

            // прокручиваем карточку (включая только что раскрытую часть) в видимую область
            var card = header.Parent == null ? null : (header.Parent as FrameworkElement)?.Parent as FrameworkElement;
            if (select && card != null)
            {
                Dispatcher.BeginInvoke(new Action(() => card.BringIntoView()),
                    DispatcherPriority.Loaded);
            }
        }

        // Экспорт всей страницы (все открытые карточки) в HTML-файл. Работает и офлайн.
        private void Export_Click(object sender, RoutedEventArgs e)
        {
            ExportCommand.Run(_url, _items);
        }

        private void Back_Click(object sender, RoutedEventArgs e)
        {
            BackRequested?.Invoke(this, EventArgs.Empty);
        }
    }
}