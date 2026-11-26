
using System;
using System.Globalization;
using System.Text;

namespace Project_check_URL
{
    internal static class HtmlScan
    {
        internal static string Clean(string s, int max)
        {
            if (s == null) return null;

            var sb = new StringBuilder(Math.Min(s.Length, max));
            bool space = false;

            foreach (char c in s)
            {
                UnicodeCategory cat = char.GetUnicodeCategory(c);

                if (char.IsWhiteSpace(c) ||
                    cat == UnicodeCategory.LineSeparator ||
                    cat == UnicodeCategory.ParagraphSeparator)
                {
                    if (!space && sb.Length > 0)
                        sb.Append(' ');

                    space = true;
                    continue;
                }

                if (cat == UnicodeCategory.Control ||
                    cat == UnicodeCategory.Format)
                    continue;

                space = false;
                sb.Append(c);

                if (sb.Length >= max)
                {
                    sb.Append("...");
                    break;
                }
            }

            return sb.ToString().Trim();
        }
    }
}
