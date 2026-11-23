using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Media.Animation;

namespace Project_check_URL.View
{
    public partial class LoginView : UserControl
    {
        public event EventHandler LoginSucceeded;

        public LoginView()
        {
            InitializeComponent();
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            string user = UsernameTextBox.Text.Trim();
            string pass = PasswordBox.Password;

            if (user == "" || pass == "")
            {
                MessageBox.Show("Enter your account and password");
                return;
            }

            try
            {
                if (UserRepository.Login(user, pass))
                {
                    LoginSucceeded?.Invoke(this, EventArgs.Empty);
                    
                } 
                else
                    MessageBox.Show("Incorrect account password");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Errol with connection to data base\n" + ex.Message);
            }
        }
        private void Register_Click(object sender, RoutedEventArgs e)
        {
            ShowCard(RegisterCard, LoginCard);
            RegUsernameTextBox.Focus();
        }

        
        private void BackToLogin_Click(object sender, RoutedEventArgs e)
        {
            ShowCard(LoginCard, RegisterCard);
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            string user = RegUsernameTextBox.Text.Trim();
            string pass = RegPasswordBox.Password;
            string confirm = RegConfirmBox.Password;

            if (user == "" || pass == "")
            {
                MessageBox.Show("Enter your account and password");
                return;
            }
            if (pass.Length < 6)
            {
                MessageBox.Show("Your password must be at least 6 character.");
                return;
            }
            if (pass != confirm)
            {
                MessageBox.Show("Incorrect password");
                return;
            }

            try
            {
                if (UserRepository.Register(user, pass))
                {
                    MessageBox.Show("Register successfull. Turn back to LoginSpace");


                    UsernameTextBox.Clear();
                    PasswordBox.Clear();
                    RegUsernameTextBox.Clear();
                    RegPasswordBox.Clear();
                    RegConfirmBox.Clear();

                    ShowCard(LoginCard, RegisterCard);
                    PasswordBox.Focus();
                }
                else
                {
                    MessageBox.Show("Errol, this account's name has been used");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Errol with connection to data base\n" + ex.Message);
            }
        }
        private void ShowCard(Border show, Border hide)
        {
            hide.Visibility = Visibility.Collapsed;

            LoginButton.IsDefault = (show == LoginCard);
            RegisterButton.IsDefault = (show == RegisterCard);

            show.Visibility = Visibility.Visible;
            show.BeginAnimation(UIElement.OpacityProperty,
                new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(250)));
        }
    }
}
