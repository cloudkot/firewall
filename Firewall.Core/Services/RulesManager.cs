using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Firewall.Core.Models;
using Firewall.Core.Helpers;

namespace Firewall.Core.Services
{
    public class RulesManager
    {
        private ObservableCollection<FirewallRule> _rules = new ObservableCollection<FirewallRule>();
        private int _nextId = 1;
        private WfpService _wfp = new WfpService();
        private readonly object _blockIpLock = new object();


        public ObservableCollection<FirewallRule> Rules => _rules;

        public bool IsIPBlocked(string ip)
        {
            return _rules.Any(r => r.RemoteIP == ip && r.Action == "Блок" && (r.IsTemporary || !r.IsTemporary));
        }
        public void AddRule(FirewallRule rule)
        {
            rule.Id = _nextId++;
            _rules.Add(rule);
            _wfp.AddRule(rule);
            JsonHelper.SaveRules(_rules);

            if (rule.TimeAction != "Постоянно" && rule.ExpiryTime.HasValue)
            {
                var delay = rule.ExpiryTime.Value - DateTime.Now;
                if (delay > TimeSpan.Zero)
                {
                    Task.Delay(delay).ContinueWith(_ =>
                    {
                        if (Application.Current != null)
                            Application.Current.Dispatcher.Invoke(() => RemoveRule(rule));
                        else
                            RemoveRule(rule); 
                    });
                }
            }
        }

        public void RemoveRule(FirewallRule rule)
        {
            _rules.Remove(rule);
            _wfp.RemoveRule(rule.Name);
            JsonHelper.SaveRules(_rules);
        }

        public void UpdateRule(FirewallRule oldRule, FirewallRule newRule)
        {
            var index = _rules.IndexOf(oldRule);
            if (index >= 0)
            {
                newRule.Id = oldRule.Id;
                _rules[index] = newRule;
                _wfp.RemoveRule(oldRule.Name);
                _wfp.AddRule(newRule);
                JsonHelper.SaveRules(_rules);
            }
        }

        public void LoadAndApplyFromFile()
        {
            var loaded = JsonHelper.LoadRules();
            foreach (var rule in loaded)
                AddRule(rule);
        }

        public void ApplyAllRules()
        {
            foreach (var rule in _rules.Where(r => r.IsEnabled))
                _wfp.AddRule(rule);
        }

        public void ClearAllActiveRules()
        {
            _wfp.ClearAllRules();
        }

        public void ClearAllRules()
        {
            _wfp.ClearAllRules();
            _rules.Clear();
            JsonHelper.SaveRules(_rules);
        }

        public void RemoveTemporaryRulesForIP(string ip)
        {
            var toRemove = _rules.Where(r => r.IsTemporary && r.RemoteIP == ip).ToList();
            foreach (var rule in toRemove)
            {
                RemoveRule(rule);
            }
        }

        public void BlockIP(string ip, int minutes = 5)
        {
            lock (_blockIpLock)
            {
                var existing = _rules.FirstOrDefault(r =>
                    r.RemoteIP == ip &&
                    r.Action == "Блок" &&
                    r.IsTemporary &&
                    r.IsEnabled &&
                    (!r.ExpiryTime.HasValue || r.ExpiryTime.Value > DateTime.Now)
                );

                if (existing != null)
                {
                    existing.ExpiryTime = DateTime.Now.AddMinutes(minutes);
                    existing.TimeAction = $"На {minutes} минут";

                    JsonHelper.SaveRules(_rules); return;
                }

                var rule = new FirewallRule
                {
                    Name = $"AutoBlock_{ip}_{DateTime.Now:yyyyMMddHHmmss}",
                    Direction = "Оба",
                    Action = "Блок",
                    RemoteIP = ip,
                    IsEnabled = true,
                    IsTemporary = true,
                    TimeAction = $"На {minutes} минут",
                    ExpiryTime = DateTime.Now.AddMinutes(minutes)
                };
                AddRule(rule); 
            }
        }
    }
}