using System;
using System.Collections.Generic;
using System.Linq;
using System.Timers;

namespace Firewall.Core.Services
{
    public class SimpleIdsService : IDisposable
    {
        private readonly Dictionary<string, HashSet<int>> _scanners = new Dictionary<string, HashSet<int>>();
        private readonly Timer _resetTimer;
        private readonly int _portThreshold;
        private readonly int _timeWindowSeconds;
        private readonly object _lock = new object();

        public event Action<string, int> SuspiciousActivityDetected; // IP, количество портов

        public SimpleIdsService(int portThreshold = 20, int timeWindowSeconds = 10)
        {
            _portThreshold = portThreshold;
            _timeWindowSeconds = timeWindowSeconds;
            _resetTimer = new Timer(_timeWindowSeconds * 1000);
            _resetTimer.Elapsed += (s, e) => CheckAndReport();
            _resetTimer.AutoReset = true;
            _resetTimer.Start();
        }

        public void AddConnection(string sourceIp, int remotePort)
        {
            if (sourceIp == "127.0.0.1" || sourceIp == "0.0.0.0") return;

            lock (_lock)
            {
                if (!_scanners.TryGetValue(sourceIp, out var ports))
                {
                    ports = new HashSet<int>();
                    _scanners[sourceIp] = ports;
                }
                ports.Add(remotePort);
            }
        }

        private void CheckAndReport()
        {
            Dictionary<string, HashSet<int>> snapshot;

            // Блокируем на время копирования данных
            lock (_lock)
            {
                snapshot = _scanners.ToDictionary(
                    kv => kv.Key,
                    kv => new HashSet<int>(kv.Value) // копируем порты для безопасного чтения
                );
                _scanners.Clear();
            }

            // Анализируем копию без блокировки
            foreach (var kv in snapshot)
            {
                if (kv.Value.Count >= _portThreshold)
                {
                    SuspiciousActivityDetected?.Invoke(kv.Key, kv.Value.Count);
                }
            }
        }

        public void Dispose()
        {
            _resetTimer?.Stop();
            _resetTimer?.Dispose();
        }
    }
}