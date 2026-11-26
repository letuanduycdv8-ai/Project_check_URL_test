using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using Project_check_URL.View;

namespace Project_check_URL
{
    // ------------------------------------------------------------------
    // Xuất kết quả kiểm tra ra một file HTML độc lập (không cần thư viện ngoài).
    //
    // Báo cáo được dựng thẳng từ dữ liệu (CheckItem / DetailLine), KHÔNG chụp lại
    // giao diện, nên không phụ thuộc vào việc thẻ nào đang đóng/mở trong DetailView:
    // mọi thẻ luôn được viết ra ở trạng thái "đã bấm mở" (đủ About, Details, Assessment).
    //
    // Muốn có PDF: mở file HTML trong trình duyệt -> Ctrl+P -> "Save as PDF".
    // CSS đã có @media print để cắt trang gọn.
    // ------------------------------------------------------------------
    public static class ReportExporter
    {
        private const string OfflineNote =
            "Not available in offline mode. Turn on Online mode and check the link again.";

        // Phải khớp thứ tự nhóm của DetailView.GroupOf: 0 = static, 1 = VirusTotal, 2 = HTML
        private static readonly string[] SectionNumbers  = { "1", "2", "3" };
        private static readonly string[] SectionTitles   = { "STATIC CHECK", "VIRUSTOTAL RESULT", "HTML ANALYSIS" };
        private static readonly string[] SectionSubtitles =
        {
            "Offline analysis of the link and its domain name",
            "How the security engines on VirusTotal rate this URL",
            "What the web server answers: status, redirects, content type and the start of the page"
        };
        private static readonly string[] SectionEmptyText =
        {
            "No static results.", OfflineNote, OfflineNote
        };

        private static string E(string s)
        {
            return WebUtility.HtmlEncode(s ?? "");
        }

        // Giống DetailEntry.Level: giá trị lạ coi là Warning
        private static string LevelOf(CheckItem item)
        {
            string l = item.Level;
            return (l == "Safe" || l == "Danger") ? l : "Warning";
        }

        private static string FindingOf(CheckItem item)
        {
            return string.IsNullOrWhiteSpace(item.Finding) ? "No details reported." : item.Finding;
        }

        private static string AdviceOf(CheckItem item, string level)
        {
            return string.IsNullOrWhiteSpace(item.Assessment)
                ? DetailView.AdviceFor(level)
                : item.Assessment;
        }

        public static string BuildHtml(string url, IEnumerable<CheckItem> items)
        {
            var list = (items ?? Enumerable.Empty<CheckItem>()).ToList();

            int safe = list.Count(i => LevelOf(i) == "Safe");
            int warn = list.Count(i => LevelOf(i) == "Warning");
            int danger = list.Count(i => LevelOf(i) == "Danger");
            string overall = danger > 0 ? "Danger" : warn > 0 ? "Warning" : "Safe";

            var sb = new StringBuilder(16 * 1024);
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">");
            // Báo cáo chỉ là văn bản tĩnh: chặn mọi script/tài nguyên ngoài cho chắc
            sb.AppendLine("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.AppendLine("<title>URL check report</title>");
            sb.AppendLine("<style>").Append(Css).AppendLine("</style></head><body><main>");

            sb.AppendLine("<header class=\"top\">");
            sb.AppendLine("<h1>URL check report</h1>");
            // URL chỉ hiện dạng chữ, KHÔNG phải link bấm được: link có thể độc hại
            sb.Append("<p class=\"url\">").Append(E(url)).AppendLine("</p>");
            sb.Append("<p class=\"meta\">Generated ")
              .Append(E(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz")))
              .AppendLine("</p>");
            sb.Append("<div class=\"summary\"><span class=\"badge lvl-").Append(overall).Append("\">")
              .Append(overall.ToUpperInvariant()).Append("</span>")
              .Append("<span class=\"count lvl-Safe\">").Append(safe).Append(" Safe</span>")
              .Append("<span class=\"count lvl-Warning\">").Append(warn).Append(" Warning</span>")
              .Append("<span class=\"count lvl-Danger\">").Append(danger).AppendLine(" Danger</span></div>");
            sb.AppendLine("</header>");

            // Chia nhóm đúng như DetailView
            var groups = new List<CheckItem>[3];
            for (int g = 0; g < 3; g++) groups[g] = new List<CheckItem>();
            foreach (CheckItem it in list)
                groups[DetailView.GroupOf(it.Criterion)].Add(it);

            for (int g = 0; g < 3; g++)
            {
                sb.AppendLine("<section class=\"group\">");
                sb.Append("<h2><span class=\"num\">").Append(SectionNumbers[g]).Append("</span>")
                  .Append(E(SectionTitles[g])).AppendLine("</h2>");
                sb.Append("<p class=\"sub\">").Append(E(SectionSubtitles[g])).AppendLine("</p>");

                if (groups[g].Count == 0)
                {
                    sb.Append("<p class=\"empty\">").Append(E(SectionEmptyText[g])).AppendLine("</p>");
                }
                else
                {
                    foreach (CheckItem it in groups[g])
                        AppendCard(sb, it);
                }
                sb.AppendLine("</section>");
            }

            sb.AppendLine("<footer>Generated by Project check URL. A clean result lowers risk but does not prove a link is safe.</footer>");
            sb.AppendLine("</main></body></html>");
            return sb.ToString();
        }

        // Một thẻ ở trạng thái đã mở hoàn toàn
        private static void AppendCard(StringBuilder sb, CheckItem it)
        {
            string level = LevelOf(it);

            sb.Append("<article class=\"card lvl-").Append(level).AppendLine("\">");
            sb.Append("<div class=\"card-head\"><span class=\"badge lvl-").Append(level).Append("\">")
              .Append(level).Append("</span><h3>").Append(E(it.Criterion)).AppendLine("</h3></div>");
            sb.Append("<p class=\"finding\">").Append(E(FindingOf(it))).AppendLine("</p>");

            sb.Append("<div class=\"block\"><div class=\"label\">About this check</div><p>")
              .Append(E(DetailView.AboutFor(it.Criterion))).AppendLine("</p></div>");

            if (it.Details != null && it.Details.Count > 0)
            {
                sb.AppendLine("<div class=\"block\"><div class=\"label\">Details</div><table class=\"details\">");
                foreach (DetailLine line in it.Details)
                {
                    if (line.IsHeading)
                        sb.Append("<tr class=\"h\"><th colspan=\"2\">").Append(E(line.Label)).AppendLine("</th></tr>");
                    else
                        sb.Append("<tr><td class=\"k\">").Append(E(line.Label)).Append("</td><td class=\"v\">")
                          .Append(E(line.Value)).AppendLine("</td></tr>");
                }
                sb.AppendLine("</table></div>");
            }

            sb.Append("<div class=\"block advice\"><div class=\"label\">Assessment</div><p>")
              .Append(E(AdviceOf(it, level))).AppendLine("</p></div>");
            sb.AppendLine("</article>");
        }

        private const string Css = @"
:root{--safe:#1b7f4b;--warn:#b86e00;--danger:#c0262d;--ink:#1c2733;--mut:#5c6b7a;--line:#d9e0e7;--bg:#f4f6f9}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif;
 -webkit-print-color-adjust:exact;print-color-adjust:exact}
main{max-width:860px;margin:0 auto;padding:28px 20px}
h1{margin:0 0 6px;font-size:24px}
.url{margin:0;padding:10px 12px;background:#fff;border:1px solid var(--line);border-radius:8px;
 font-family:Consolas,monospace;word-break:break-all}
.meta{margin:6px 0 12px;color:var(--mut);font-size:12px}
.summary{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-weight:700;font-size:12px}
.count{padding:2px 10px;border-radius:999px;border:1px solid currentColor;font-weight:600;font-size:12px}
.badge.lvl-Safe{background:var(--safe)}.badge.lvl-Warning{background:var(--warn)}.badge.lvl-Danger{background:var(--danger)}
.count.lvl-Safe{color:var(--safe)}.count.lvl-Warning{color:var(--warn)}.count.lvl-Danger{color:var(--danger)}
.group{margin-top:26px}
h2{margin:0;font-size:16px;letter-spacing:.04em;display:flex;align-items:center;gap:8px}
.num{display:inline-flex;width:22px;height:22px;border-radius:50%;background:var(--ink);color:#fff;
 align-items:center;justify-content:center;font-size:12px}
.sub{margin:2px 0 10px;color:var(--mut)}
.empty{padding:12px;background:#fff;border:1px dashed var(--line);border-radius:8px;color:var(--mut)}
.card{background:#fff;border:1px solid var(--line);border-left:5px solid var(--mut);border-radius:8px;
 padding:12px 14px;margin:0 0 12px;break-inside:avoid;page-break-inside:avoid}
.card.lvl-Safe{border-left-color:var(--safe)}.card.lvl-Warning{border-left-color:var(--warn)}.card.lvl-Danger{border-left-color:var(--danger)}
.card-head{display:flex;align-items:center;gap:10px}
h3{margin:0;font-size:15px}
.finding{margin:6px 0 8px;font-weight:600;white-space:pre-wrap;overflow-wrap:anywhere}
.block{margin-top:8px}
.label{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
.block p{margin:2px 0 0;overflow-wrap:anywhere}
table.details{width:100%;border-collapse:collapse;margin-top:4px;font-size:13px}
table.details td,table.details th{padding:4px 8px;border-top:1px solid var(--line);vertical-align:top;text-align:left}
td.k{width:30%;color:var(--mut)}
td.v{white-space:pre-wrap;overflow-wrap:anywhere;font-family:Consolas,monospace}
tr.h th{background:#eef2f6;font-size:12px;letter-spacing:.04em}
footer{margin-top:24px;color:var(--mut);font-size:12px;text-align:center}
@media print{body{background:#fff}main{max-width:none;padding:0}@page{margin:14mm}}
";
    }
}
