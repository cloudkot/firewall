using System;
using System.Collections.Generic;
using Firewall.Core.Models;
using H.Firewall;

namespace Firewall.Core.Services
{
    public class WfpService : IDisposable
    {
        private readonly Dictionary<string, IDisposable> _activeRules = new Dictionary<string, IDisposable>();

        public void AddRule(FirewallRule rule)
        {
            if (!rule.IsEnabled) return;
            if (_activeRules.ContainsKey(rule.Name)) RemoveRule(rule.Name);

            var builder = new FirewallBuilder();
            if (rule.Action == "Блок")
                builder.Block();
            else
                builder.Allow();

            if (!string.IsNullOrEmpty(rule.ApplicationPath))
                builder.Application(rule.ApplicationPath);

            _activeRules[rule.Name] = builder.Build();
        }

        public void RemoveRule(string ruleName)
        {
            if (_activeRules.TryGetValue(ruleName, out var disposable))
            {
                disposable.Dispose();
                _activeRules.Remove(ruleName);
            }
        }

        public void BlockIP(string ip, int minutes)
        {
            var rule = new FirewallRule
            {
                Name = $"IDS_Block_{ip}",
                Direction = "Оба",
                Action = "Блок",
                RemoteIP = ip,
                IsEnabled = true,
                IsTemporary = true,
                ExpiryTime = DateTime.Now.AddMinutes(minutes),
                TimeAction = $"На {minutes} минут"
            };
            AddRule(rule);
        }

        public void ClearAllRules()
        {
            foreach (var rule in _activeRules.Values)
                rule.Dispose();
            _activeRules.Clear();
        }

        public void Dispose()
        {
            ClearAllRules();
        }
    }
}