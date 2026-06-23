using System.Collections.ObjectModel;
using System.IO;
using Firewall.Core.Models;
using Newtonsoft.Json;

namespace Firewall.Core.Helpers
{
    public static class JsonHelper
    {
        internal static string RulesFilePath = @"C:\ProgramData\Firewall\rules.json";

        public static void SaveRules(ObservableCollection<FirewallRule> rules)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(RulesFilePath));
            var json = JsonConvert.SerializeObject(rules, Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText(RulesFilePath, json);
        }

        public static ObservableCollection<FirewallRule> LoadRules()
        {
            if (!File.Exists(RulesFilePath))
                return new ObservableCollection<FirewallRule>();
            var json = File.ReadAllText(RulesFilePath);
            return JsonConvert.DeserializeObject<ObservableCollection<FirewallRule>>(json)
                   ?? new ObservableCollection<FirewallRule>();
        }
        public static ObservableCollection<FirewallRule> LoadRulesFromFile(string filePath)
        {
            if (!File.Exists(filePath)) return new ObservableCollection<FirewallRule>();
            var json = File.ReadAllText(filePath);
            return JsonConvert.DeserializeObject<ObservableCollection<FirewallRule>>(json) ?? new ObservableCollection<FirewallRule>();
        }

        public static void SaveRulesToFile(ObservableCollection<FirewallRule> rules, string filePath)
        {
            var json = JsonConvert.SerializeObject(rules, Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText(filePath, json);
        }
    }
}