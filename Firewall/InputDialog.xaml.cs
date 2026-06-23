using System.Windows;

namespace Firewall
{
    public partial class InputDialog : Window
    {
        public string Answer => MinutesBox.Text;

        public InputDialog()
        {
            InitializeComponent();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
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