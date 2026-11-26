using System;
using System.IO;
using System.Linq;
using System.Windows;

namespace Project_check_URL
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
#if !DEBUG
            if (!IsIntegrityOk(out string reason))
            {
                MessageBox.Show(reason, "Project check URL",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
                return; // не вызываем base.OnStartup => ни одно окно не откроется
            }
#endif
            base.OnStartup(e);
        }

        private static bool IsIntegrityOk(out string reason)
        {
            reason = null;
            try
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                string manifestPath = Path.Combine(dir, "integrity.manifest");
                string sigPath = Path.Combine(dir, "integrity.manifest.sig");

                if (!File.Exists(manifestPath) || !File.Exists(sigPath))
                {
                    reason = "Missing integrity.manifest or signature file.";
                    return false;
                }

                byte[] manifest = File.ReadAllBytes(manifestPath);
                string sig = File.ReadAllText(sigPath);

                if (!ManifestVerifier.Verify(manifest, sig))
                {
                    reason = "Manifest signature is invalid.";
                    return false;
                }

                var errors = IntegrityChecker.VerifyFiles(dir, manifest);
                if (errors.Count > 0)
                {
                    reason = "Changes detected:\n" +
                             string.Join("\n", errors.Take(5));
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                reason = "Cannot verify integrity: " + ex.Message;
                return false;
            }
        }
    }
}