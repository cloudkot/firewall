using System;

namespace Firewall.Core.Models
{
    public class LogEntry
    {
        public DateTime Time { get; set; }
        public string EventType { get; set; }
        public string Message { get; set; }
        public string IP { get; set; }
        public string ApplicationPath { get; set; }
    }
}