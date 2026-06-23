using Firewall.Core.Models;
using Microsoft.Win32;
using System;
using System.Windows;
using System.Windows.Controls;

namespace Firewall
{

    public partial class RuleDialog : Window
    {
        public FirewallRule Rule { get; private set; }

        public RuleDialog(FirewallRule editRule = null)
        {
            InitializeComponent();
            if (editRule != null)
            {
                tbName.Text = editRule.Name;
                cbDirection.SelectedItem = FindComboBoxItem(cbDirection, editRule.Direction);
                cbAction.SelectedItem = FindComboBoxItem(cbAction, editRule.Action == "Блок" ? "Блок" : "Разрешить");
                cbProtocol.SelectedItem = FindComboBoxItem(cbProtocol, editRule.Protocol);
                tbLocalPort.Text = editRule.LocalPort;
                tbRemoteIP.Text = editRule.RemoteIP;
                tbAppPath.Text = editRule.ApplicationPath ?? "";
                chkEnabled.IsChecked = editRule.IsEnabled;
            }
        }

        private ComboBoxItem FindComboBoxItem(ComboBox combo, string content)
        {
            foreach (ComboBoxItem item in combo.Items)
                if (item.Content.ToString() == content)
                    return item;
            return null;
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog();
            dialog.Filter = "Исполняемые файлы (*.exe)|*.exe|Все файлы (*.*)|*.*";
            if (dialog.ShowDialog() == true)
                tbAppPath.Text = dialog.FileName;
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(tbName.Text))
            {
                MessageBox.Show("Введите имя правила.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string timeAction = ((ComboBoxItem)cbTimeAction.SelectedItem).Content.ToString();
            DateTime? expiry = null;
            if (timeAction == "На 1 час")
                expiry = DateTime.Now.AddHours(1);
            else if (timeAction == "На 5 минут")
                expiry = DateTime.Now.AddMinutes(5);
            else if (timeAction == "На 15 минут")
                expiry = DateTime.Now.AddMinutes(15);
            // "На сеанс" – не ставим expiry, но запомним, что временное

            Rule = new FirewallRule
            {
                Name = tbName.Text.Trim(),
                Direction = ((ComboBoxItem)cbDirection.SelectedItem).Content.ToString(),
                Action = ((ComboBoxItem)cbAction.SelectedItem).Content.ToString() == "Блок" ? "Блок" : "Разрешить",
                Protocol = ((ComboBoxItem)cbProtocol.SelectedItem).Content.ToString(),
                LocalPort = tbLocalPort.Text.Trim(),
                RemoteIP = tbRemoteIP.Text.Trim(),
                ApplicationPath = string.IsNullOrWhiteSpace(tbAppPath.Text) ? null : tbAppPath.Text.Trim(),
                IsEnabled = chkEnabled.IsChecked == true,
                TimeAction = timeAction,
                ExpiryTime = expiry
            };
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