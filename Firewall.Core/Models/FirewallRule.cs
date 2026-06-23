using System;

namespace Firewall.Core.Models
{
    public class FirewallRule
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Action { get; set; }      // "Блок" или "Разрешить"
        public string Direction { get; set; }   // "Исходящий", "Входящий", "Оба"
        public string Protocol { get; set; }    // "TCP", "UDP", "ICMP"
        public string LocalPort { get; set; }   // "80", "443", "5000-5010", "Все"
        public string RemoteIP { get; set; }    // "192.168.1.1", "192.168.1.0/24", "Любой"
        public string ApplicationPath { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsTemporary { get; set; }
        public DateTime? ExpiryTime { get; set; }

        public string TimeAction { get; set; } = "Постоянно";
    }
}