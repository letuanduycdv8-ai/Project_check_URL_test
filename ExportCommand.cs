using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using Project_check_URL.View;

namespace Project_check_URL
{
    // ------------------------------------------------------------------
    // Общее для кнопки Export в HomeView и DetailView:
    // диалог сохранения файла -> запись HTML-отчёта -> открытие только что экспортированного файла.
    // Всё выполняется локально, интернет не требуется.
    // ------------------------------------------------------------------
    public static class ExportCommand
    {
        public static void Run(string url, IEnumerable<CheckItem> items, Action<string> setStatus = null)
        {
            List<CheckItem> list = (items ?? Enumerable.Empty<CheckItem>()).ToList();
            if (list.Count == 0)
            {
                MessageBox.Show("There is no result to export. Check a link first.",
                    "Export report", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export report",
                Filter = "HTML report (*.html)|*.html",
                DefaultExt = ".html",
                AddExtension = true,
                FileName = "URL-report-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".html"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                string html = ReportExporter.BuildHtml(url, list);
                System.IO.File.WriteAllText(dlg.FileName, html, new UTF8Encoding(true));
                setStatus?.Invoke("Report exported");

                System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not export the report:\n" + ex.Message,
                    "Export report", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}