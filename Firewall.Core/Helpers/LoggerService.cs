using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using Firewall.Core.Models; // используем единую модель LogEntry (если она есть в Models, удалите из Helpers)

namespace Firewall.Core.Helpers
{
    public static class LoggerService
    {
        private static readonly string LogDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Firewall");
        private static readonly string LogFile = Path.Combine(LogDirectory, "logs.txt");
        private static readonly string DbFile = Path.Combine(LogDirectory, "logs.db");

        static LoggerService()
        {
            if (!Directory.Exists(LogDirectory))
                Directory.CreateDirectory(LogDirectory);

            if (!File.Exists(DbFile))
            {
                SQLiteConnection.CreateFile(DbFile);
                using (var conn = new SQLiteConnection($"Data Source={DbFile}"))
                {
                    conn.Open();
                    var cmd = new SQLiteCommand("CREATE TABLE IF NOT EXISTS Logs (Id INTEGER PRIMARY KEY AUTOINCREMENT, Time TEXT, EventType TEXT, Message TEXT, IP TEXT, App TEXT)", conn);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public static void LogEvent(string message, string eventType = "Info", string ip = "", string app = "")
        {
            string logLine = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{eventType}] {message}";
            if (!string.IsNullOrEmpty(ip))
                logLine += $" | IP={ip}";
            if (!string.IsNullOrEmpty(app))
                logLine += $" | App={app}";
            System.IO.File.AppendAllText(LogFile, logLine + Environment.NewLine);

            using (var conn = new SQLiteConnection($"Data Source={DbFile}"))
            {
                conn.Open();
                var cmd = new SQLiteCommand("INSERT INTO Logs (Time, EventType, Message, IP, App) VALUES (@time, @type, @msg, @ip, @app)", conn);
                cmd.Parameters.AddWithValue("@time", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@type", eventType);
                cmd.Parameters.AddWithValue("@msg", message);
                cmd.Parameters.AddWithValue("@ip", string.IsNullOrEmpty(ip) ? "" : ip);
                cmd.Parameters.AddWithValue("@app", string.IsNullOrEmpty(app) ? "" : app);
                cmd.ExecuteNonQuery();
            }
        }

        public static List<LogEntry> LoadLogs()
        {
            var result = new List<LogEntry>();
            if (!File.Exists(DbFile)) return result;

            using (var conn = new SQLiteConnection($"Data Source={DbFile}"))
            {
                conn.Open();
                var cmd = new SQLiteCommand("SELECT Time, EventType, Message, IP, App FROM Logs ORDER BY Time DESC", conn);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        result.Add(new LogEntry
                        {
                            Time = DateTime.Parse(reader["Time"].ToString()),
                            EventType = reader["EventType"].ToString(),
                            Message = reader["Message"].ToString(),
                            IP = reader["IP"].ToString(),
                            ApplicationPath = reader["App"].ToString()
                        });
                    }
                }
            }
            return result;
        }

        public static void ClearAllLogs()
        {
            if (File.Exists(DbFile))
            {
                using (var conn = new SQLiteConnection($"Data Source={DbFile}"))
                {
                    conn.Open();
                    new SQLiteCommand("DELETE FROM Logs", conn).ExecuteNonQuery();
                }
            }
            if (File.Exists(LogFile))
                File.WriteAllText(LogFile, "");
        }

        public static void ExportToCsvWithStats(string filePath)
        {
            var logs = LoadLogs();
            using (var writer = new StreamWriter(filePath))
            {
                writer.WriteLine("=== СТАТИСТИКА ===");
                writer.WriteLine($"Всего событий: {logs.Count}");
                writer.WriteLine("Топ заблокированных приложений (по упоминаниям):");
                var blockedApps = logs.Where(l => l.EventType == "Block" && !string.IsNullOrEmpty(l.ApplicationPath))
                                      .GroupBy(l => l.ApplicationPath)
                                      .OrderByDescending(g => g.Count())
                                      .Take(5);
                foreach (var app in blockedApps)
                    writer.WriteLine($"{app.Key}, {app.Count()}");
                writer.WriteLine("Топ заблокированных IP:");
                var blockedIPs = logs.Where(l => l.EventType == "Block" && !string.IsNullOrEmpty(l.IP))
                                      .GroupBy(l => l.IP)
                                      .OrderByDescending(g => g.Count())
                                      .Take(5);
                foreach (var ip in blockedIPs)
                    writer.WriteLine($"{ip.Key}, {ip.Count()}");
                writer.WriteLine();
                writer.WriteLine("=== ДЕТАЛЬНЫЕ ЛОГИ ===");
                writer.WriteLine("Time,EventType,Message,IP,Application");
                foreach (var log in logs)
                    writer.WriteLine($"{log.Time},{log.EventType},{log.Message},{log.IP},{log.ApplicationPath}");
            }
        }
    }
}