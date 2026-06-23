using System.Windows;
using Firewall.Core.Helpers;

namespace Firewall
{
    public partial class PasswordInputDialog : Window
    {
        public PasswordInputDialog()
        {
            InitializeComponent();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            string pwd = PasswordBox.Password;
            if (string.IsNullOrEmpty(pwd))
            {
                ErrorText.Text = "Введите пароль";
                ErrorText.Visibility = Visibility.Visible;
                return;
            }
            if (SettingsHelper.VerifyPassword(pwd))
            {
                DialogResult = true;
                Close();
            }
            else
            {
                ErrorText.Text = "Неверный пароль";
                ErrorText.Visibility = Visibility.Visible;
                // Не закрываем окно, даём ещё одну попытку
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}