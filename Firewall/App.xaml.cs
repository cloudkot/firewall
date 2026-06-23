using Firewall.Core.Helpers;
using System.Threading.Tasks;
using System.Windows;

namespace Firewall
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // 1. Создаём главное окно (но пока скрываем)
            var mainWindow = new MainWindow();
            mainWindow.Visibility = Visibility.Hidden;

            // 2. Проверяем, нужен ли пароль
            bool protectionEnabled = SettingsHelper.IsPasswordProtectionEnabled();
            bool hashExists = SettingsHelper.IsPasswordHashExists();

            if (protectionEnabled && hashExists)
            {
                var login = new PasswordInputDialog();
                if (login.ShowDialog() != true)
                {
                    Shutdown();
                    return;
                }
            }

            // 3. Показываем главное окно
            Task.Delay(50).ContinueWith(_ =>
            {
                var mainWindow = new MainWindow();
                mainWindow.Show();
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }
    }
}