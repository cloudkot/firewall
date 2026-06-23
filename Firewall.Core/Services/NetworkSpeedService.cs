using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace Firewall.Core.Services
{
    public class NetworkSpeedService : IDisposable
    {
        private PerformanceCounter _receivedCounter;
        private PerformanceCounter _sentCounter;
        private Timer _timer;
        private double _smoothReceived;
        private double _smoothSent;
        private const double SmoothFactor = 0.15;
        private bool _firstValue = true;

        public event Action<double, double> SpeedUpdated;




        public NetworkSpeedService(string interfaceName = null)
        {


            if (string.IsNullOrEmpty(interfaceName))
            {
                var category = new PerformanceCounterCategory("Network Interface");
                var instances = category.GetInstanceNames();
                // Выводим список в Debug
                Debug.WriteLine("Доступные интерфейсы:");
                foreach (var inst in instances)
                    Debug.WriteLine($"  {inst}");
                // Выбираем первый не Loopback и не Virtual
                interfaceName = instances.FirstOrDefault(i =>
                    !i.Contains("Loopback") &&
                    !i.Contains("Virtual") &&
                    !i.Contains("VPN") &&
                    !i.Contains("Adapter")
                );
            }

            try
            {
                if (string.IsNullOrEmpty(interfaceName))
                {
                    var category = new PerformanceCounterCategory("Network Interface");
                    var instances = category.GetInstanceNames();
                    foreach (var inst in instances)
                    {
                        if (!inst.Contains("Loopback") && !inst.Contains("Virtual"))
                        {
                            interfaceName = inst;
                            break;
                        }
                    }
                    if (string.IsNullOrEmpty(interfaceName) && instances.Length > 0)
                        interfaceName = instances[0];
                }

                if (!string.IsNullOrEmpty(interfaceName))
                {
                    _receivedCounter = new PerformanceCounter("Network Interface", "Bytes Received/sec", interfaceName);
                    _sentCounter = new PerformanceCounter("Network Interface", "Bytes Sent/sec", interfaceName);
                    _receivedCounter.NextValue();
                    _sentCounter.NextValue();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"NetworkSpeedService init error: {ex.Message}");
                _receivedCounter = null;
                _sentCounter = null;
            }

            // Интервал 100 мс для плавности
            _timer = new Timer(UpdateSpeed, null, 0, 100);
        }

        public static List<string> GetAvailableInterfaces()
        {
            var result = new List<string>();
            try
            {
                var category = new PerformanceCounterCategory("Network Interface");
                var instances = category.GetInstanceNames();
                result.AddRange(instances.Where(i => !i.Contains("Loopback") && !i.Contains("Virtual")));
                if (result.Count == 0 && instances.Length > 0)
                    result.Add(instances[0]);
            }
            catch { }
            return result;
        }

        private void UpdateSpeed(object state)
        {

            if (_receivedCounter == null || _sentCounter == null)
            {
                SpeedUpdated?.Invoke(0, 0);
                return;
            }

            double received = Math.Max(0, _receivedCounter.NextValue());
            double sent = Math.Max(0, _sentCounter.NextValue());

            if (_firstValue)
            {
                _smoothReceived = received;
                _smoothSent = sent;
                _firstValue = false;
            }
            else
            {
                _smoothReceived = _smoothReceived * (1 - SmoothFactor) + received * SmoothFactor;
                _smoothSent = _smoothSent * (1 - SmoothFactor) + sent * SmoothFactor;
            }

            SpeedUpdated?.Invoke(_smoothReceived, _smoothSent);
        }

        public void Dispose()
        {
            _timer?.Dispose();
            _receivedCounter?.Dispose();
            _sentCounter?.Dispose();
        }
    }
}