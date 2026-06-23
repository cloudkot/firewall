using System.Windows;

namespace Firewall
{
    public partial class PasswordSetDialog : Window
    {
        public string NewPassword => NewPasswordBox.Password;

        public PasswordSetDialog()
        {
            InitializeComponent();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            string pwd = NewPasswordBox.Password;
            string confirm = ConfirmPasswordBox.Password;
            if (string.IsNullOrEmpty(pwd))
            {
                ErrorText.Text = "Пароль не может быть пустым";
                ErrorText.Visibility = Visibility.Visible;
                return;
            }
            if (pwd != confirm)
            {
                ErrorText.Text = "Пароли не совпадают";
                ErrorText.Visibility = Visibility.Visible;
                return;
            }
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}