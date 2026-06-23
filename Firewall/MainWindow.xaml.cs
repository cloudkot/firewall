using Firewall.Core.Helpers;
using Firewall.Core.Models;
using Firewall.Core.Services;
using Hardcodet.Wpf.TaskbarNotification;
using Microsoft.Win32;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Firewall
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private RulesManager _rulesManager;
        private ActiveConnectionsService _connectionsService;
        private NetworkSpeedService _speedService;
        private ObservableCollection<ActiveConnection> _connections = new ObservableCollection<ActiveConnection>();
        private ObservableCollection<LogEntry> _logs = new ObservableCollection<LogEntry>();
        private DispatcherTimer _autoRefreshTimer;
        private FileSystemWatcher _watcher;
        private bool _loadingSettings = false;
        private bool _isIsolationMode = false;
        private IDisposable _isolationRule = null;
        private DispatcherTimer _idsTimer;
        private Dictionary<string, HashSet<int>> _portScanTracker = new Dictionary<string, HashSet<int>>();
        private DateTime _lastScanReset = DateTime.Now;
        private bool _isFirewallEnabled = false;
        private string _originalFirewallPolicy = null;

        // График
        private PlotModel _plotModel;
        private LineSeries _receivedSeries;
        private LineSeries _sentSeries;
        private DateTime _startTime;
        private bool _isGraphActive = true;
        private readonly object _graphLock = new object();
        private string _selectedInterface = null;

        private Hardcodet.Wpf.TaskbarNotification.TaskbarIcon _trayIcon;

        private void ShowNotification(string title, string message)
        {
            if (ShowNotificationsCheck.IsChecked == true)
            {
                _trayIcon?.ShowBalloonTip(title, message, Hardcodet.Wpf.TaskbarNotification.BalloonIcon.Info);
            }
        }

        public PlotModel PlotModel
        {
            get => _plotModel;
            set { _plotModel = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        public MainWindow()
        {
            try { InitializeComponent(); }
            catch (Exception ex)
            {
                MessageBox.Show($"InitializeComponent failed: {ex.Message}\n{ex.StackTrace}");
                throw;
            }
            DataContext = this;

            LogTypeCombo.SelectedIndex = 0; // 0 = Сетевые события

            // Заполнение списка интерфейсов
            var interfaces = NetworkSpeedService.GetAvailableInterfaces();
            InterfaceCombo.ItemsSource = interfaces;
            if (interfaces.Count > 0)
            {
                InterfaceCombo.SelectedIndex = 0;
                _selectedInterface = interfaces[0];
            }

            // Инициализация трея
            _trayIcon = new Hardcodet.Wpf.TaskbarNotification.TaskbarIcon
            {
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location),
                ToolTipText = "Firewall Guard",
                Visibility = Visibility.Visible
            };
            _trayIcon.TrayMouseDoubleClick += (s, e) => ShowWindow();

            // Контекстное меню (WPF)
            var menu = new ContextMenu();
            var showItem = new MenuItem { Header = "Показать окно" };
            showItem.Click += (s, e) => ShowWindow();
            var exitItem = new MenuItem { Header = "Выход" };
            exitItem.Click += (s, e) => Application.Current.Shutdown();
            menu.Items.Add(showItem);
            menu.Items.Add(exitItem);
            _trayIcon.ContextMenu = menu;

            // График
            _plotModel = new PlotModel
            {
                Title = null,
                Background = OxyColors.Black,
                PlotAreaBorderColor = OxyColors.DarkGray,
                PlotAreaBorderThickness = new OxyThickness(1)
            };
            _plotModel.Axes.Add(new LinearAxis
            {
                Position = AxisPosition.Bottom,
                IsAxisVisible = true,
                Title = null,
                TextColor = OxyColors.White,
                TickStyle = TickStyle.None,
                MajorGridlineStyle = LineStyle.Dot,
                MajorGridlineColor = OxyColors.Gray,
                MinorGridlineStyle = LineStyle.None,
                Minimum = 0,
                Maximum = 30,
                IsPanEnabled = false,
                IsZoomEnabled = false,
                LabelFormatter = value => ""          // скрываем цифры
            });
            _plotModel.Axes.Add(new LinearAxis
            {
                Position = AxisPosition.Left,
                Title = "байт/с",
                TextColor = OxyColors.White,
                TickStyle = TickStyle.Inside,
                MajorGridlineStyle = LineStyle.Dot,
                MajorGridlineColor = OxyColors.Gray,
                MinorGridlineStyle = LineStyle.None,
                Minimum = 0,
                IsPanEnabled = false,
                IsZoomEnabled = false
            });
            _receivedSeries = new LineSeries
            {
                Title = "Входящие",
                Color = OxyColors.SpringGreen,
                StrokeThickness = 2,
                MarkerSize = 0,
                LineStyle = LineStyle.Solid,
                CanTrackerInterpolatePoints = false
            };
            _sentSeries = new LineSeries
            {
                Title = "Исходящие",
                Color = OxyColors.DodgerBlue,
                StrokeThickness = 2,
                MarkerSize = 0,
                LineStyle = LineStyle.Solid,
                CanTrackerInterpolatePoints = false
            };
            _plotModel.Series.Add(_receivedSeries);
            _plotModel.Series.Add(_sentSeries);
            SpeedPlot.Model = _plotModel;

            _startTime = DateTime.Now;

            // Создаём сервис скорости с выбранным интерфейсом
            _speedService = new NetworkSpeedService(_selectedInterface);
            _speedService.SpeedUpdated += OnSpeedUpdated;

            // Подписки на события пароля
            EnablePasswordCheck.Checked += PasswordProtection_Changed;
            EnablePasswordCheck.Unchecked += PasswordProtection_Changed;

            // Подписки на мгновенное сохранение настроек для чекбоксов
            AutoStartCheck.Checked += (s, e) => SettingsHelper.SetAutoStart(true);
            AutoStartCheck.Unchecked += (s, e) => SettingsHelper.SetAutoStart(false);
            ShowNotificationsCheck.Checked += (s, e) => SettingsHelper.SetShowNotifications(true);
            ShowNotificationsCheck.Unchecked += (s, e) => SettingsHelper.SetShowNotifications(false);
            PlaySoundCheck.Checked += (s, e) => SettingsHelper.SetPlaySound(true);
            PlaySoundCheck.Unchecked += (s, e) => SettingsHelper.SetPlaySound(false);

            _rulesManager = new RulesManager();
            _connectionsService = new ActiveConnectionsService();

            Loaded += MainWindow_Loaded;
            ConnectionsGrid.ItemsSource = _connections;
            LogsGrid.ItemsSource = _logs;
            LoadLogs();
            RefreshConnections();

            _autoRefreshTimer = new DispatcherTimer();
            _autoRefreshTimer.Interval = TimeSpan.FromSeconds(2);
            _autoRefreshTimer.Tick += (s, e) => { if (AutoRefreshCheck.IsChecked == true) RefreshConnections(); };
            _autoRefreshTimer.Start();

            StartWatchingRules();

            StartIdsMonitoring(); // IDS мониторинг

            LoggerService.LogEvent("Приложение запущено.", "System");
        }

        private void ShowWindow()
        {
            this.Show();
            this.WindowState = WindowState.Normal;
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            e.Cancel = true;
            Hide();
            _trayIcon.ShowBalloonTip("FirewallGuard", "Приложение свернуто в трей", BalloonIcon.Info);
        }

        private void OnSpeedUpdated(double recv, double sent)
        {
            if (!_isGraphActive) return;
            Dispatcher.Invoke(() =>
            {
                try
                {
                    double now = (DateTime.Now - _startTime).TotalSeconds;
                    _receivedSeries.Points.Add(new DataPoint(now, recv));
                    _sentSeries.Points.Add(new DataPoint(now, sent));

                    const int maxPoints = 600;
                    while (_receivedSeries.Points.Count > maxPoints) _receivedSeries.Points.RemoveAt(0);
                    while (_sentSeries.Points.Count > maxPoints) _sentSeries.Points.RemoveAt(0);

                    if (_plotModel.Axes.Count > 0 && _plotModel.Axes[0] is LinearAxis xAxis)
                    {
                        xAxis.Minimum = now - 30;
                        xAxis.Maximum = now;
                        xAxis.MajorStep = 5;
                        xAxis.MinorStep = 1;
                    }

                    if (_plotModel.Axes.Count > 1 && _plotModel.Axes[1] is LinearAxis yAxis)
                    {
                        double maxY = 0;
                        foreach (var p in _receivedSeries.Points) maxY = Math.Max(maxY, p.Y);
                        foreach (var p in _sentSeries.Points) maxY = Math.Max(maxY, p.Y);
                        yAxis.Maximum = maxY > 0 ? maxY * 1.05 : 100;
                    }

                    _plotModel.InvalidatePlot(true);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Ошибка в SpeedUpdated: {ex.Message}");
                }
            });
        }

        private void InterfaceCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (InterfaceCombo.SelectedItem == null) return;
            string newInterface = InterfaceCombo.SelectedItem.ToString();
            if (newInterface == _selectedInterface) return;

            // Останавливаем старый сервис
            _speedService?.Dispose();

            // Создаём новый сервис с выбранным интерфейсом
            _selectedInterface = newInterface;
            _speedService = new NetworkSpeedService(_selectedInterface);
            _speedService.SpeedUpdated += OnSpeedUpdated;

            // Сбрасываем точки на графике
            _receivedSeries?.Points.Clear();
            _sentSeries?.Points.Clear();
            _startTime = DateTime.Now;

            LoggerService.LogEvent($"Переключен интерфейс на {_selectedInterface}", "System");
        }

        private void UpdateFirewallStatus()
        {
            if (_isFirewallEnabled)
            {
                FirewallStatusDot.Fill = System.Windows.Media.Brushes.LimeGreen;
                FirewallStatusDot.ToolTip = "Фаервол включён";
            }
            else
            {
                FirewallStatusDot.Fill = System.Windows.Media.Brushes.Red;
                FirewallStatusDot.ToolTip = "Фаервол выключен";
            }
        }

        private string GetCurrentFirewallPolicy()
        {
            var process = new Process();
            process.StartInfo.FileName = "netsh";
            process.StartInfo.Arguments = "advfirewall show allprofiles";
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            return output;
        }

        private void StartIdsMonitoring()
        {
            _idsTimer = new DispatcherTimer();
            _idsTimer.Interval = TimeSpan.FromSeconds(10);
            _idsTimer.Tick += IdsTimer_Tick;
            _idsTimer.Start();
        }

        private void IdsTimer_Tick(object sender, EventArgs e)
        {
            Dictionary<string, HashSet<int>> snapshot;
            lock (_portScanTracker)
            {
                snapshot = new Dictionary<string, HashSet<int>>(_portScanTracker);
            }

            if ((DateTime.Now - _lastScanReset).TotalSeconds >= 10)
            {
                foreach (var kv in snapshot)
                {
                    if (kv.Value.Count >= 20)
                    {
                        var msg = $"Обнаружено сканирование портов с IP {kv.Key} (портов: {kv.Value.Count})";
                        LoggerService.LogEvent(msg, "IDS");
                        ShowNotification("Подозрительный трафик", msg);
                        _rulesManager.BlockIP(kv.Key);
                    }
                }
                lock (_portScanTracker)
                {
                    _portScanTracker.Clear();
                }
                _lastScanReset = DateTime.Now;
            }

            foreach (var conn in _connections)
            {
                if (conn.RemoteAddress != "0.0.0.0:0" && conn.RemoteAddress != "127.0.0.1:0" && conn.RemoteAddress.Contains(":"))
                {
                    var parts = conn.RemoteAddress.Split(':');
                    if (parts.Length == 2 && int.TryParse(parts[1], out int port))
                    {
                        string ip = parts[0];
                        lock (_portScanTracker)
                        {
                            if (!_portScanTracker.ContainsKey(ip))
                                _portScanTracker[ip] = new HashSet<int>();
                            _portScanTracker[ip].Add(port);
                        }
                    }
                }
            }
        }

        private void SetFirewallPolicy(bool blockAll)
        {
            string args = blockAll
                ? "advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
                : "advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound";
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = args,
                    Verb = "runas",
                    CreateNoWindow = true,
                    UseShellExecute = false
                }
            };
            process.Start();
            process.WaitForExit();
        }

        private void IsolationMode_Click(object sender, RoutedEventArgs e)
        {
            if (!_isIsolationMode)
            {
                _rulesManager.ClearAllActiveRules();
                SetFirewallPolicy(true);  // блокировать всё
                _isIsolationMode = true;
                IsolationBtn.Content = "🔓 Отключить изоляцию";
                LoggerService.LogEvent("Режим полной изоляции включён.", "System");
                MessageBox.Show("Режим полной изоляции активирован. Весь трафик заблокирован.", "Изоляция");
            }
            else
            {
                SetFirewallPolicy(false); // разрешить всё
                _rulesManager.ApplyAllRules();
                _isIsolationMode = false;
                IsolationBtn.Content = "🔒 Полная изоляция";
                LoggerService.LogEvent("Режим изоляции отключён.", "System");
                MessageBox.Show("Режим изоляции отключён. Правила восстановлены.", "Изоляция");
            }
        }

        private void RefreshGrid()
        {
            RulesGrid.ItemsSource = null;
            RulesGrid.ItemsSource = _rulesManager.Rules;
        }

        private void StartGraph_Click(object sender, RoutedEventArgs e)
        {
            _isGraphActive = true;
            LoggerService.LogEvent("График скорости запущен.", "System");
        }

        private void StopGraph_Click(object sender, RoutedEventArgs e)
        {
            _isGraphActive = false;
            LoggerService.LogEvent("График скорости остановлен.", "System");
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _loadingSettings = true;
            AutoStartCheck.IsChecked = SettingsHelper.GetAutoStart();
            ShowNotificationsCheck.IsChecked = SettingsHelper.GetShowNotifications();
            PlaySoundCheck.IsChecked = SettingsHelper.GetPlaySound();

            bool pwdEnabled = SettingsHelper.IsPasswordProtectionEnabled() && SettingsHelper.IsPasswordHashExists();
            EnablePasswordCheck.IsChecked = pwdEnabled;
            ChangePasswordBtn.IsEnabled = pwdEnabled;
            _loadingSettings = false;

            var currentVersion = Assembly.GetExecutingAssembly().GetName().Version;
            Task.Run(async () =>
            {
                if (await UpdateChecker.CheckForUpdate(currentVersion))
                {
                    Dispatcher.Invoke(() =>
                        ShowNotification("Обновление", "Доступна новая версия. Посетите сайт."));
                }
            });

            _rulesManager.LoadAndApplyFromFile();
            RulesGrid.ItemsSource = _rulesManager.Rules;
            UpdateStats();

            var hasActiveRules = _rulesManager.Rules.Any(r => r.IsEnabled);
            _isFirewallEnabled = hasActiveRules;
            UpdateFirewallStatus();

            // Очистка просроченных правил после загрузки
            var expired = _rulesManager.Rules.Where(r => r.ExpiryTime.HasValue && r.ExpiryTime.Value <= DateTime.Now).ToList();
            foreach (var rule in expired) _rulesManager.RemoveRule(rule);
        }

        private void UpdateStats()
        {
            int activeRulesCount = _rulesManager.Rules.Count(r => r.IsEnabled);
            RulesCount.Text = activeRulesCount.ToString();

            var logs = LoggerService.LoadLogs();
            int blocked = logs.Count(l => l.EventType == "Block");
            int allowed = logs.Count(l => l.EventType == "Allow");
            BlockedCount.Text = blocked.ToString();
            AllowedCount.Text = allowed.ToString();
        }

        private void BlockedCount_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            MainTabControl.SelectedIndex = 3; // вкладка Логи
            LogSearchBox.Text = "Block";
            FilterLogs_Click(null, null);
        }

        private void AllowedCount_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            MainTabControl.SelectedIndex = 3;
            LogSearchBox.Text = "Allow";
            FilterLogs_Click(null, null);
        }

        private void RulesCount_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            MainTabControl.SelectedIndex = 1; // вкладка Правила
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new RuleDialog();
            if (dialog.ShowDialog() == true && dialog.Rule != null)
            {
                _rulesManager.AddRule(dialog.Rule);
                RefreshGrid();
                UpdateStats();
                LoggerService.LogEvent($"Добавлено правило: {dialog.Rule.Name}", "Rule");
            }
        }

        private void EditRule_Click(object sender, RoutedEventArgs e)
        {
            var selected = RulesGrid.SelectedItem as FirewallRule;
            if (selected == null)
            {
                MessageBox.Show("Выберите правило для редактирования.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            var dialog = new RuleDialog(selected);
            if (dialog.ShowDialog() == true && dialog.Rule != null)
            {
                _rulesManager.UpdateRule(selected, dialog.Rule);
                RefreshGrid();
                UpdateStats();
                LoggerService.LogEvent($"Изменено правило: {dialog.Rule.Name}", "Rule");
            }
        }

        private void DeleteRule_Click(object sender, RoutedEventArgs e)
        {
            var selected = RulesGrid.SelectedItem as FirewallRule;
            if (selected == null)
            {
                MessageBox.Show("Выберите правило для удаления.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (MessageBox.Show($"Удалить правило '{selected.Name}'?", "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                _rulesManager.RemoveRule(selected);
                RefreshGrid();
                UpdateStats();
                LoggerService.LogEvent($"Удалено правило: {selected.Name}", "Rule");
            }
        }

        private void EnableFirewall_Click(object sender, RoutedEventArgs e)
        {
            _rulesManager.ApplyAllRules();
            MessageBox.Show("Фаервол включен.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
            LoggerService.LogEvent("Фаервол включён пользователем.", "System");

            _isFirewallEnabled = true;
            UpdateFirewallStatus();
        }

        private void DisableFirewall_Click(object sender, RoutedEventArgs e)
        {
            _rulesManager.ClearAllActiveRules();
            MessageBox.Show("Фаервол отключен.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
            LoggerService.LogEvent("Фаервол отключён пользователем.", "System");

            _isFirewallEnabled = false;
            UpdateFirewallStatus();
        }

        private void ResetRules_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Удалить ВСЕ правила? Это действие необратимо.", "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
            {
                _rulesManager.ClearAllRules();
                RefreshGrid();
                UpdateStats();
                MessageBox.Show("Все правила удалены.", "Готово", MessageBoxButton.OK, MessageBoxImage.Information);
                LoggerService.LogEvent("Все правила сброшены.", "System");
            }
        }

        private void ImportRules_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog { Filter = "JSON files (*.json)|*.json" };
            if (dialog.ShowDialog() == true)
            {
                var imported = JsonHelper.LoadRulesFromFile(dialog.FileName);
                foreach (var rule in imported) _rulesManager.AddRule(rule);
                RefreshGrid();
                UpdateStats();
                MessageBox.Show($"Импортировано {imported.Count} правил.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                LoggerService.LogEvent($"Импортировано {imported.Count} правил из {dialog.FileName}", "System");
            }
        }

        private void ExportRules_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog { Filter = "JSON files (*.json)|*.json", FileName = "firewall_rules.json" };
            if (dialog.ShowDialog() == true)
            {
                JsonHelper.SaveRulesToFile(_rulesManager.Rules, dialog.FileName);
                MessageBox.Show("Правила экспортированы.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                LoggerService.LogEvent($"Правила экспортированы в {dialog.FileName}", "System");
            }
        }

        private void RefreshConnections_Click(object sender, RoutedEventArgs e) => RefreshConnections();

        private void RefreshConnections()
        {
            try
            {
                var list = _connectionsService.GetConnections();
                _connections.Clear();
                foreach (var conn in list) _connections.Add(conn);
                ConnectionsStatus.Text = $"Соединений: {_connections.Count}";
            }
            catch (Exception ex) { Debug.WriteLine($"Ошибка: {ex.Message}"); }
        }

        private void BlockAppFromConnection_Click(object sender, RoutedEventArgs e)
        {
            var conn = ConnectionsGrid.SelectedItem as ActiveConnection;
            if (conn == null) return;
            try
            {
                var process = Process.GetProcessById(conn.PID);
                var path = process.MainModule.FileName;
                var rule = new FirewallRule
                {
                    Name = $"Блокировка {conn.ProcessName}",
                    Direction = "Оба",
                    Action = "Блок",
                    Protocol = "TCP",
                    ApplicationPath = path,
                    IsEnabled = true,
                    IsTemporary = false
                };
                _rulesManager.AddRule(rule);
                RefreshGrid();
                UpdateStats();
                LoggerService.LogEvent($"Заблокировано приложение {conn.ProcessName} (PID {conn.PID})", "Block");
                MessageBox.Show($"Приложение {conn.ProcessName} заблокировано.", "Успех");
            }
            catch (Exception ex) { MessageBox.Show($"Ошибка: {ex.Message}"); }
        }

        private void BlockIPFromConnection_Click(object sender, RoutedEventArgs e)
        {
            var conn = ConnectionsGrid.SelectedItem as ActiveConnection;
            if (conn == null) return;
            var ip = conn.RemoteAddress.Split(':')[0];
            if (ip == "0.0.0.0" || ip == "127.0.0.1") return;
            var rule = new FirewallRule
            {
                Name = $"Блокировка IP {ip}",
                Direction = "Оба",
                Action = "Блок",
                RemoteIP = ip,
                IsEnabled = true,
                IsTemporary = false
            };
            _rulesManager.AddRule(rule);
            RefreshGrid();
            UpdateStats();
            LoggerService.LogEvent($"Заблокирован IP {ip}", "Block");
            MessageBox.Show($"IP {ip} заблокирован.", "Успех");
        }

        private async void TemporaryBlockApp_Click(object sender, RoutedEventArgs e)
        {
            var conn = ConnectionsGrid.SelectedItem as ActiveConnection;
            if (conn == null) return;
            var dialog = new InputDialog();
            if (dialog.ShowDialog() == true && int.TryParse(dialog.Answer, out int minutes) && minutes > 0)
            {
                try
                {
                    var process = Process.GetProcessById(conn.PID);
                    var path = process.MainModule.FileName;
                    var rule = new FirewallRule
                    {
                        Name = $"Врем.блокировка {conn.ProcessName}",
                        Direction = "Оба",
                        Action = "Блок",
                        ApplicationPath = path,
                        IsEnabled = true,
                        IsTemporary = true,
                        ExpiryTime = DateTime.Now.AddMinutes(minutes)
                    };
                    _rulesManager.AddRule(rule);
                    RefreshGrid();
                    UpdateStats();
                    LoggerService.LogEvent($"Временная блокировка {conn.ProcessName} на {minutes} мин", "Block");
                    MessageBox.Show($"Приложение {conn.ProcessName} заблокировано на {minutes} минут.", "Успех");

                    await Task.Delay(TimeSpan.FromMinutes(minutes));
                    Dispatcher.Invoke(() =>
                    {
                        _rulesManager.RemoveRule(rule);
                        RefreshGrid();
                        UpdateStats();
                        LoggerService.LogEvent($"Временная блокировка {conn.ProcessName} истекла.", "System");
                    });
                }
                catch (Exception ex) { MessageBox.Show($"Ошибка: {ex.Message}"); }
            }
        }

        private void LoadLogs()
        {
            _logs.Clear();
            var allLogs = LoggerService.LoadLogs();
            var filtered = FilterLogsByType(allLogs);
            foreach (var log in filtered) _logs.Add(log);
            if (LogsStatus != null) LogsStatus.Text = $"Записей: {_logs.Count}";
        }

        private void LogTypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            LoadLogs();
        }

        private List<LogEntry> FilterLogsByType(List<LogEntry> allLogs)
        {
            string selected = (LogTypeCombo.SelectedItem as ComboBoxItem)?.Content.ToString();
            if (selected == "Сетевые события")
                return allLogs.Where(l => l.EventType == "Block" || l.EventType == "Allow" || l.EventType == "IDS").ToList();
            else
                return allLogs.Where(l => l.EventType != "Block" && l.EventType != "Allow" && l.EventType != "IDS").ToList();
        }

        private void FilterLogs_Click(object sender, RoutedEventArgs e)
        {
            string search = LogSearchBox.Text?.ToLower() ?? "";
            if (string.IsNullOrWhiteSpace(search))
            {
                LoadLogs();
            }
            else
            {
                var allLogs = LoggerService.LoadLogs();
                var byType = FilterLogsByType(allLogs);
                var filtered = byType.Where(l =>
                    (l.Message != null && l.Message.ToLower().Contains(search)) ||
                    (l.IP != null && l.IP.Contains(search))).ToList();
                _logs.Clear();
                foreach (var log in filtered) _logs.Add(log);
                if (LogsStatus != null) LogsStatus.Text = $"Найдено: {_logs.Count}";
            }
        }

        private void ExportLogs_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog { Filter = "CSV files (*.csv)|*.csv", FileName = "firewall_logs.csv" };
            if (dialog.ShowDialog() == true)
            {
                LoggerService.ExportToCsvWithStats(dialog.FileName);
                MessageBox.Show("Логи экспортированы со статистикой.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ClearLogs_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Очистить все логи?", "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                LoggerService.ClearAllLogs();
                _logs.Clear();
                LogsStatus.Text = "Записей: 0";
            }
        }

        private void PasswordProtection_Changed(object sender, RoutedEventArgs e)
        {
            if (_loadingSettings) return;

            bool enabled = EnablePasswordCheck.IsChecked == true;

            if (enabled)
            {
                // Всегда открываем диалог установки пароля при включении защиты
                var setDlg = new PasswordSetDialog();
                if (setDlg.ShowDialog() == true && !string.IsNullOrEmpty(setDlg.NewPassword))
                {
                    SettingsHelper.SavePasswordHash(setDlg.NewPassword);
                    SettingsHelper.SetPasswordProtectionEnabled(true);
                    ChangePasswordBtn.IsEnabled = true;
                    MessageBox.Show("Пароль установлен.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoggerService.LogEvent("Пароль установлен (включена защита).", "System");
                }
                else
                {
                    // Пользователь отменил или не ввёл пароль – снимаем чекбокс
                    EnablePasswordCheck.IsChecked = false;
                    SettingsHelper.SetPasswordProtectionEnabled(false);
                    ChangePasswordBtn.IsEnabled = false;
                }
            }
            else
            {
                // Отключаем защиту
                SettingsHelper.SetPasswordProtectionEnabled(false);
                ChangePasswordBtn.IsEnabled = false;
                LoggerService.LogEvent("Защита паролем отключена.", "System");
            }
        }

        private void ChangePassword_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new PasswordSetDialog();
            if (dialog.ShowDialog() == true && !string.IsNullOrEmpty(dialog.NewPassword))
            {
                SettingsHelper.SavePasswordHash(dialog.NewPassword);
                MessageBox.Show("Пароль изменён.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                LoggerService.LogEvent("Пароль изменён пользователем.", "System");
            }
        }

        private void BackupConfig_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog { Filter = "Backup files (*.fbk)|*.fbk", FileName = "firewall_backup.fbk" };
            if (dialog.ShowDialog() == true)
            {
                SettingsHelper.BackupConfiguration(dialog.FileName);
                MessageBox.Show("Резервная копия создана.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RestoreConfig_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog { Filter = "Backup files (*.fbk)|*.fbk" };
            if (dialog.ShowDialog() == true)
            {
                SettingsHelper.RestoreConfiguration(dialog.FileName);
                _rulesManager.LoadAndApplyFromFile();
                RefreshGrid();
                UpdateStats();
                MessageBox.Show("Конфигурация восстановлена.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void StartWatchingRules()
        {
            var path = @"C:\ProgramData\Firewall";
            var file = "rules.json";
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);
            _watcher = new FileSystemWatcher(path, file);
            _watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime;
            _watcher.Changed += OnRulesFileChanged;
            _watcher.EnableRaisingEvents = true;
        }

        private async void OnRulesFileChanged(object sender, FileSystemEventArgs e)
        {
            await Task.Delay(500);
            Dispatcher.Invoke(() =>
            {
                _rulesManager.LoadAndApplyFromFile();
                RefreshGrid();
                UpdateStats();
                LoggerService.LogEvent("Правила автоматически перезагружены из файла.", "System");
            });
        }
    }
}