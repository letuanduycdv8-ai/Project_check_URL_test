using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Project_check_URL.View;

namespace Project_check_URL
{
    public partial class MainWindow : Window
    {
        private bool _isSwitching;
        private HomeView _home;

        public MainWindow()
        {
            InitializeComponent();
            MainContent.RenderTransform = new TranslateTransform();
            ShowLogin();
        }

        private void ShowLogin()
        {
            var login = new LoginView();
            login.LoginSucceeded += (s, e) => ShowHome();
            MainContent.Content = login;
        }

        private void ShowHome()
        {
            if (_home == null)
            {
                _home = new HomeView();
                _home.DetailRequested += (s, e) => ShowDetail(e);
            }
            SwitchTo(_home);
        }
        private void ShowDetail(DetailRequestedEventArgs args)
        {
            var detail = new DetailView(args.Url, args.Items);
            detail.BackRequested += (s, e) => ShowHome();
            SwitchTo(detail);
        }

        private void SwitchTo(UIElement newView)
        {
            if (_isSwitching) return;          
            _isSwitching = true;
            MainContent.IsHitTestVisible = false;   

            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(350))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };

            fadeOut.Completed += (s, e) =>
            {
                MainContent.Content = newView;

                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(500))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                var slide = new DoubleAnimation(24, 0, TimeSpan.FromMilliseconds(500))
                {
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };

                fadeIn.Completed += (s2, e2) =>
                {
                    
                    MainContent.BeginAnimation(OpacityProperty, null);
                    MainContent.Opacity = 1;
                    MainContent.IsHitTestVisible = true;
                    _isSwitching = false;
                };

                MainContent.BeginAnimation(OpacityProperty, fadeIn);
                ((TranslateTransform)MainContent.RenderTransform)
                    .BeginAnimation(TranslateTransform.YProperty, slide);
            };

            MainContent.BeginAnimation(OpacityProperty, fadeOut);
        }
    }
}