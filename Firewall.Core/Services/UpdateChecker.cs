using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Firewall.Core.Services
{
    public static class UpdateChecker
    {
        private const string VersionUrl = "https://raw.githubusercontent.com/cloudkot/firewall-landing/version.txt";

        private static readonly HttpClient _httpClient = new HttpClient();

        public static async Task<bool> CheckForUpdate(Version currentVersion)
        {
            try
            {
                string latestVersionStr = await _httpClient.GetStringAsync(VersionUrl);
                latestVersionStr = latestVersionStr.Trim();

                if (Version.TryParse(latestVersionStr, out Version latestVersion))
                {
                    return latestVersion > currentVersion;
                }
                else
                {
                    // Версия в файле не распарсилась
                    System.Diagnostics.Debug.WriteLine($"Не удалось распарсить версию: {latestVersionStr}");
                    return false;
                }
            }
            catch (HttpRequestException ex)
            {
                // Ошибка сети — например, нет интернета или файл не найден
                System.Diagnostics.Debug.WriteLine($"Ошибка проверки обновлений: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                // Другие ошибки
                System.Diagnostics.Debug.WriteLine($"Неизвестная ошибка: {ex.Message}");
                return false;
            }
        }
    }
}