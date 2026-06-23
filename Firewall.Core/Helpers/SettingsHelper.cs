using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace Firewall.Core.Helpers
{
    public static class SettingsHelper
    {
        private const string RegistryPath = @"Software\FirewallGuard";

        // --- Парольная защита ---
        public static void SetPasswordProtectionEnabled(bool enabled)
        {
            using (var key = Registry.CurrentUser.CreateSubKey(RegistryPath))
                key.SetValue("PasswordProtectionEnabled", enabled ? 1 : 0, RegistryValueKind.DWord);
        }

        public static bool IsPasswordProtectionEnabled()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
                return (int)key?.GetValue("PasswordProtectionEnabled", 0) == 1;
        }

        public static bool IsPasswordHashExists()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
            {
                return key?.GetValue("PasswordHash") != null;
            }
        }

        public static void SavePasswordHash(string password)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
                string hashString = Convert.ToBase64String(hash);
                using (var key = Registry.CurrentUser.CreateSubKey(RegistryPath))
                    key.SetValue("PasswordHash", hashString, RegistryValueKind.String);
            }
        }

        public static bool VerifyPassword(string password)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
            {
                string stored = (string)key?.GetValue("PasswordHash", "");
                if (string.IsNullOrEmpty(stored)) return false;
                using (var sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
                    string computed = Convert.ToBase64String(hash);
                    return stored == computed;
                }
            }
        }
        static SettingsHelper()
        {
            // Создаём раздел реестра при первом использовании
            using (var key = Registry.CurrentUser.CreateSubKey(RegistryPath)) { }
        }


        // --- Автозапуск ---
        public static void SetAutoStart(bool enabled)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, true))
                key.SetValue("AutoStart", enabled, RegistryValueKind.DWord);

            var appName = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name;
            var appPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true))
            {
                if (enabled)
                    key.SetValue(appName, appPath);
                else
                    key.DeleteValue(appName, false);
            }
        }

        public static bool GetAutoStart()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
                return (int)key.GetValue("AutoStart", 0) == 1;
        }

        // --- Сворачивать в трей ---
        public static void SetMinimizeToTray(bool enabled)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, true))
                key.SetValue("MinimizeToTray", enabled, RegistryValueKind.DWord);
        }

        public static bool GetMinimizeToTray()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
                return (int)key.GetValue("MinimizeToTray", 0) == 1;
        }

        // --- Показывать уведомления ---
        public static void SetShowNotifications(bool enabled)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, true))
                key.SetValue("ShowNotifications", enabled, RegistryValueKind.DWord);
        }

        public static bool GetShowNotifications()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
                return (int)key.GetValue("ShowNotifications", 0) == 1;
        }

        // --- Звук при блокировке ---
        public static void SetPlaySound(bool enabled)
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, true))
                key.SetValue("PlaySound", enabled, RegistryValueKind.DWord);
        }

        public static bool GetPlaySound()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath, false))
                return (int)key.GetValue("PlaySound", 0) == 1;
        }

        // --- Резервное копирование (ваши существующие методы) ---
        public static void BackupConfiguration(string backupPath)
        {
            var rulesFile = @"C:\ProgramData\Firewall\rules.json";
            if (File.Exists(rulesFile))
                File.Copy(rulesFile, backupPath, true);
        }

        public static void RestoreConfiguration(string backupPath)
        {
            var rulesFile = @"C:\ProgramData\Firewall\rules.json";
            if (File.Exists(backupPath))
                File.Copy(backupPath, rulesFile, true);
        }
    }
}