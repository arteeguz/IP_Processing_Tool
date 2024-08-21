using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using IP_Processing_Tool;
using Microsoft.Win32;

namespace IPProcessingTool
{
    public partial class MainWindow : Window
    {
        private string outputFilePath;
        public ObservableCollection<ScanStatus> ScanStatuses { get; set; }
        private CancellationTokenSource cancellationTokenSource;
        private ParallelOptions parallelOptions;
        private ObservableCollection<ColumnSetting> dataColumnSettings;
        private bool autoSave;
        private int pingTimeout = 1000; // Default value
        private int totalIPs;
        private int processedIPs;

        public MainWindow()
        {
            InitializeComponent();
            ScanStatuses = new ObservableCollection<ScanStatus>();
            StatusDataGrid.ItemsSource = ScanStatuses;

            parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            dataColumnSettings = new ObservableCollection<ColumnSetting>();
            autoSave = false; // Default value

            InitializeColumnSettings();
            UpdateDataGridColumns();

            Logger.Log(LogLevel.INFO, "Application started");
        }

        private void InitializeColumnSettings()
        {
            dataColumnSettings = new ObservableCollection<ColumnSetting>
            {
                new ColumnSetting { Name = "IP Address", IsSelected = true },
                new ColumnSetting { Name = "Hostname", IsSelected = true },
                new ColumnSetting { Name = "Last Logged User", IsSelected = false },
                new ColumnSetting { Name = "Machine Type", IsSelected = false },
                new ColumnSetting { Name = "Machine SKU", IsSelected = false },
                new ColumnSetting { Name = "Installed Core Software", IsSelected = false },
                new ColumnSetting { Name = "RAM Size", IsSelected = false },
                new ColumnSetting { Name = "Windows Version", IsSelected = false },
                new ColumnSetting { Name = "Windows Release", IsSelected = false },
                new ColumnSetting { Name = "Microsoft Office Version", IsSelected = false },
                new ColumnSetting { Name = "Date", IsSelected = true },
                new ColumnSetting { Name = "Time", IsSelected = true },
                new ColumnSetting { Name = "Status", IsSelected = true },
                new ColumnSetting { Name = "Details", IsSelected = true }
            };
        }
        private void UpdateDataGridColumns()
        {
            StatusDataGrid.Columns.Clear();
            foreach (var column in dataColumnSettings.Where(c => c.IsSelected))
            {
                StatusDataGrid.Columns.Add(new DataGridTextColumn
                {
                    Header = column.Name,
                    Binding = new System.Windows.Data.Binding(column.Name.Replace(" ", ""))
                });
            }
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new Settings(dataColumnSettings, autoSave, pingTimeout, parallelOptions.MaxDegreeOfParallelism);
            if (settingsWindow.ShowDialog() == true)
            {
                dataColumnSettings = new ObservableCollection<ColumnSetting>(settingsWindow.DataColumns);
                autoSave = settingsWindow.AutoSave;
                pingTimeout = settingsWindow.PingTimeout;
                parallelOptions.MaxDegreeOfParallelism = settingsWindow.MaxConcurrentScans;

                UpdateDataGridColumns();
            }
        }

        private async void Button1_Click(object sender, RoutedEventArgs e)
        {
            var inputWindow = new InputWindow("Enter the IP address:", false);
            if (inputWindow.ShowDialog() == true)
            {
                string ip = inputWindow.InputText;
                if (IsValidIP(ip))
                {
                    Logger.Log(LogLevel.INFO, "User input IP address", context: "Button1_Click", additionalInfo: ip);
                    await ProcessIPsAsync(new[] { ip });
                }
                else
                {
                    Logger.Log(LogLevel.WARNING, "Invalid IP address input", context: "Button1_Click", additionalInfo: ip);
                    ShowInvalidInputMessage();
                }
            }
        }

        private async void Button2_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv"
            };
            if (openFileDialog.ShowDialog() == true)
            {
                string csvPath = openFileDialog.FileName;

                try
                {
                    Logger.Log(LogLevel.INFO, "User selected CSV file", context: "Button2_Click", additionalInfo: csvPath);

                    var ips = File.ReadAllLines(csvPath).Select(line => line.Trim()).ToList();
                    await ProcessIPsAsync(ips);
                }
                catch (IOException ex)
                {
                    if (ex.Message.Contains("being used by another process"))
                    {
                        MessageBox.Show("The file is currently being used by another process. Please close the file and try again.", "File Access Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        //Logger.Log(LogLever.ERROR, "File access error: The file is being used by another process.", content: "Button2_Click", additionalInfo: csvPath);
                    }
                    else
                    {
                        MessageBox.Show($"An error occured while accessing the file: {ex.Message}", "File Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        //Logger.Log(LogLever.ERROR, $"File access error: {ex.Message}", Content: "Button2_Click", additionalInfo: csvPath);
                    }
                }
            }
        }

        private async void Button3_Click(object sender, RoutedEventArgs e)
        {
            var inputWindow = new InputWindow("Enter the IP segment:", true);
            if (inputWindow.ShowDialog() == true)
            {
                string segment = inputWindow.InputText;
                if (IsValidIPSegment(segment))
                {
                    Logger.Log(LogLevel.INFO, "User input IP segment", context: "Button3_Click", additionalInfo: segment);
                    var ips = Enumerable.Range(0, 256).Select(i => $"{segment}.{i}");
                    await ProcessIPsAsync(ips);
                }
                else
                {
                    Logger.Log(LogLevel.WARNING, "Invalid IP segment input", context: "Button3_Click", additionalInfo: segment);
                    ShowInvalidInputMessage();
                }
            }
        }

        private async void Button4_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv"
            };
            if (openFileDialog.ShowDialog() == true)
            {
                string csvPath = openFileDialog.FileName;

                try
                {
                    Logger.Log(LogLevel.INFO, "User selected CSV file for segment scan", context: "Button4_Click", additionalInfo: csvPath);

                    var segments = File.ReadAllLines(csvPath).Select(line => line.Trim()).ToList();
                    var ips = segments.SelectMany(segment => Enumerable.Range(0, 256).Select(i => $"{segment}.{i}"));
                    await ProcessIPsAsync(ips);
                }
                catch (IOException ex)
                {
                    if (ex.Message.Contains("being used by another process"))
                    {
                        MessageBox.Show("The file is currently being used by another process. Please close the file and try again.", "File Access Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                    else
                    {
                        MessageBox.Show($"An error occured while accessing the file: {ex.Message}", "File Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private async Task ProcessIPsAsync(IEnumerable<string> ips)
        {
            totalIPs = ips.Count();
            processedIPs = 0;
            UpdateProgressBar(0);

            DisableButtons();

            cancellationTokenSource = new CancellationTokenSource();
            var tasks = new List<Task>();

            try
            {
                foreach (var ip in ips)
                {
                    if (cancellationTokenSource.IsCancellationRequested)
                        break;

                    if (IsValidIP(ip))
                    {
                        tasks.Add(ProcessIPAsync(ip, cancellationTokenSource.Token));
                    }
                    else
                    {
                        HighlightInvalidInput(ip);
                    }

                    if (tasks.Count >= parallelOptions.MaxDegreeOfParallelism)
                    {
                        await Task.WhenAny(tasks);
                        tasks.RemoveAll(t => t.IsCompleted);
                    }
                }

                await Task.WhenAll(tasks);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, "Error processing IPs", context: "ProcessIPsAsync", additionalInfo: ex.Message);
                MessageBox.Show($"An error occurred while processing IPs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                EnableButtons();
                UpdateStatusBar("Completed processing all IPs.");
                UpdateProgressBar(100);
                HandleAutoSave();
            }
        }
        private async Task ProcessIPAsync(string ip, CancellationToken cancellationToken = default)
        {
            var scanStatus = new ScanStatus
            {
                IPAddress = ip,
                Status = "Processing",
                Details = "",
                Date = DateTime.Now.ToString("M/dd/yyyy"),
                Time = DateTime.Now.ToString("HH:mm")
            };
            AddScanStatus(scanStatus);

            UpdateStatusBar($"Processing IP: {ip} ({processedIPs + 1}/{totalIPs})");

            Logger.Log(LogLevel.INFO, "Started processing IP", context: "ProcessIPAsync", additionalInfo: ip);

            try
            {
                if (await PingHostAsync(ip, cancellationToken))
                {
                    ConnectionOptions options = new ConnectionOptions
                    {
                        Impersonation = ImpersonationLevel.Impersonate,
                        EnablePrivileges = true,
                        Authentication = System.Management.AuthenticationLevel.PacketPrivacy
                    };

                    var scope = new System.Management.ManagementScope($"\\\\{ip}\\root\\cimv2", options);
                    try
                    {
                        await Task.Run(() => scope.Connect(), cancellationToken);

                        var tasks = new List<Task>();

                        if (dataColumnSettings.Any(c => c.IsSelected && (c.Name == "Hostname" || c.Name == "Machine Type")))
                        {
                            tasks.Add(GetComputerSystemInfoAsync(scope, scanStatus, cancellationToken));
                        }

                        if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Machine SKU"))
                        {
                            tasks.Add(GetMachineSKUAsync(scope, scanStatus, cancellationToken));
                        }

                        if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Last Logged User"))
                            {
                                tasks.Add(GetLastLoggedUserAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Installed Core Software"))
                            {
                                tasks.Add(GetInstalledSoftwareAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "RAM Size"))
                            {
                                tasks.Add(GetRAMSizeAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && (c.Name == "Windows Version" || c.Name == "Windows Release")))
                            {
                                tasks.Add(GetWindowsInfoAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Microsoft Office Version"))
                            {
                                tasks.Add(GetOfficeVersionAsync(scope, scanStatus, cancellationToken));
                            }

                        await Task.WhenAll(tasks);

                        scanStatus.Status = "Complete";
                        scanStatus.Details = "N/A";
                    }
                    catch (COMException ex) when (ex.Message.Contains("The RPC server is unavailable"))
                    {
                        Logger.Log(LogLevel.WARNING, $"Failed to connect to IP {ip}. RPC server unavailable. Moving on. Error: {ex.Message}", context: "ProcessIPAsync");
                        scanStatus.Status = "Error";
                        scanStatus.Details = "The RPC server is unavailable.";
                    }
                    catch (Exception ex)
                    {
                        Logger.Log(LogLevel.WARNING, $"Failed to connect to IP {ip}. Moving on. Error: {ex.Message}", context: "ProcessIPAsync");
                        scanStatus.Status = "Error";
                        scanStatus.Details = "Failed to connect.";
                    }
                }
                else
                {
                    scanStatus.Status = "Not Reachable";
                    scanStatus.Details = "Host not reachable";
                    Logger.Log(LogLevel.WARNING, $"Host not reachable for IP {ip}", context: "ProcessIPAsync");
                }

                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException)
            {
                scanStatus.Status = "Cancelled";
                scanStatus.Details = "Operation canceled by user";
                Logger.Log(LogLevel.INFO, "Operation was canceled", context: "ProcessIPAsync");
            }
            finally
            {
                processedIPs++;
                UpdateProgressBar((int)((double)processedIPs / totalIPs * 100));
                UpdateScanStatus(scanStatus);
                UpdateStatusBar($"Completed processing IP: {ip} ({processedIPs}/{totalIPs})");
            }
        }

        private async Task GetComputerSystemInfoAsync(System.Management.ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var machineQuery = new System.Management.ObjectQuery("SELECT Name, Model FROM Win32_ComputerSystem");
                using (var machineSearcher = new System.Management.ManagementObjectSearcher(scope, machineQuery))
                {
                    var machine = await Task.Run(() => machineSearcher.Get().Cast<System.Management.ManagementObject>().FirstOrDefault(), cancellationToken);
                    if (machine != null)
                    {
                        if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Hostname"))
                            scanStatus.Hostname = machine["Name"]?.ToString() ?? "N/A";
                        if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Machine Type"))
                            scanStatus.MachineType = machine["Model"]?.ToString() ?? "N/A";
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting computer system info: {ex.Message}", context: "GetComputerSystemInfoAsync");
            }
        }

        private async Task GetMachineSKUAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var skuQuery = new ObjectQuery("SELECT Version FROM Win32_ComputerSystemProduct");
                using var skuSearcher = new ManagementObjectSearcher(scope, skuQuery);
                var sku = await Task.Run(() => skuSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                if (sku != null)
                {
                    scanStatus.MachineSKU = sku["Version"]?.ToString() ?? "N/A";
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting machine SKU: {ex.Message}", context: "GetMachineSKUAsync");
            }
        }

        private async Task GetLastLoggedUserAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var userQuery = new ObjectQuery("SELECT UserName FROM Win32_ComputerSystem");
                using var userSearcher = new ManagementObjectSearcher(scope, userQuery);
                var user = await Task.Run(() => userSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                if (user != null)
                {
                    scanStatus.LastLoggedUser = user["UserName"]?.ToString() ?? "N/A";
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting last logged user: {ex.Message}", context: "GetLastLoggedUserAsync");
            }
        }

        private async Task GetInstalledSoftwareAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var softwareQuery = new ObjectQuery("SELECT Name, Version FROM Win32_Product");
                using var softwareSearcher = new ManagementObjectSearcher(scope, softwareQuery);
                var softwareList = await Task.Run(() => softwareSearcher.Get().Cast<ManagementObject>()
                    .Select(soft => $"{soft["Name"]} ({soft["Version"]})")
                    .Take(10)
                    .ToList(), cancellationToken);
                scanStatus.InstalledCoreSoftware = string.Join(", ", softwareList);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting installed software: {ex.Message}", context: "GetInstalledSoftwareAsync");
            }
        }

        private async Task GetRAMSizeAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var ramQuery = new ObjectQuery("SELECT Capacity FROM Win32_PhysicalMemory");
                using var ramSearcher = new ManagementObjectSearcher(scope, ramQuery);
                var totalRam = await Task.Run(() => ramSearcher.Get().Cast<ManagementObject>().Sum(ram => Convert.ToDouble(ram["Capacity"])), cancellationToken);
                scanStatus.RAMSize = $"{totalRam / (1024 * 1024 * 1024):F2} GB";
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting RAM size: {ex.Message}", context: "GetRAMSizeAsync");
            }
        }

        private async Task GetWindowsInfoAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var osQuery = new ObjectQuery("SELECT Caption, BuildNumber FROM Win32_OperatingSystem");
                using var osSearcher = new ManagementObjectSearcher(scope, osQuery);
                var os = await Task.Run(() => osSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                if (os != null)
                {
                    if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Windows Version"))
                        scanStatus.WindowsVersion = os["Caption"]?.ToString() ?? "N/A";
                    if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Windows Release"))
                    {
                        string buildNumber = os["BuildNumber"]?.ToString() ?? "N/A";
                        scanStatus.WindowsRelease = MapWindowsRelease(buildNumber, scanStatus.IPAddress);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting Windows info: {ex.Message}", context: "GetWindowsInfoAsync");
            }
        }

        private async Task GetOfficeVersionAsync(string machineName, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                string officeVersion = "Not Installed";
                string registryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                string[] officeKeywords = new[] { "Microsoft Office", "Office 365", "Microsoft 365" };

                using (RegistryKey baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machineName))
                using (RegistryKey uninstallKey = baseKey.OpenSubKey(registryPath))
                {
                    if (uninstallKey != null)
                    {
                        foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                        {
                            using (RegistryKey officeKey = uninstallKey.OpenSubKey(subKeyName))
                            {
                                if (officeKey != null)
                                {
                                    string displayName = officeKey.GetValue("DisplayName") as string;
                                    string displayVersion = officeKey.GetValue("DisplayVersion") as string;

                                    if (!string.IsNullOrEmpty(displayName) && !string.IsNullOrEmpty(displayVersion))
                                    {
                                        if (officeKeywords.Any(keyword => displayName.Contains(keyword, StringComparison.OrdinalIgnoreCase)) &&
                                            !displayName.Contains("Runtime", StringComparison.OrdinalIgnoreCase) &&
                                            !displayName.Contains("Tools", StringComparison.OrdinalIgnoreCase))
                                        {
                                            officeVersion = $"{displayName} ({displayVersion})";

                                            // Determine specific version if not clear from displayName
                                            if (!displayName.Contains("365") && !displayName.Contains("2013") && !displayName.Contains("2016") && !displayName.Contains("2019"))
                                            {
                                                if (displayVersion.StartsWith("15."))
                                                    officeVersion += " (Office 2013)";
                                                else if (displayVersion.StartsWith("16."))
                                                    officeVersion += " (Office 2016 or newer)";
                                            }

                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                scanStatus.MicrosoftOfficeVersion = officeVersion;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting Microsoft Office version for {machineName}: {ex.Message}", context: "GetOfficeVersionAsync");
                scanStatus.MicrosoftOfficeVersion = "Error";
            }
        }

        private async Task<bool> PingHostAsync(string ip, CancellationToken cancellationToken)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var pingTask = ping.SendPingAsync(ip, pingTimeout, new byte[32], new PingOptions(64, true));
                    var timeoutTask = Task.Delay(pingTimeout, cancellationToken);

                    var completedTask = await Task.WhenAny(pingTask, timeoutTask);

                    if (completedTask == pingTask)
                    {
                        var reply = await pingTask;
                        return reply.Status == IPStatus.Success;
                    }
                    else
                    {
                        // Timeout occurred
                        return false;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                Logger.Log(LogLevel.INFO, $"Ping operation cancelled for IP {ip}", context: "PingHostAsync");
                throw; // Re-throw the cancellation exception to be handled by the caller
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Ping exception for IP {ip}", context: "PingHostAsync", additionalInfo: ex.Message);
                return false;
            }
        }

        private string MapWindowsRelease(string buildNumber, string ipAddress = null)
        {
            if (string.IsNullOrEmpty(buildNumber)) return "Unknown";

            switch (buildNumber)
            {
                case "19041":
                case "19042":
                case "19043":
                case "19044":
                    return "Windows 10 20H2";
                case "19045":
                    // Here, we check the DisplayVersion or ReleaseId to distinguish between 21H2 and 22H2
                    string versionDetail = GetWindowsVersionDetail(ipAddress, buildNumber);
                    return $"Windows 10 {versionDetail}";
                case "22000":
                    return "Windows 11 21H2";
                case "22621":
                case "22622":
                    return "Windows 11 22H2";
                case "22631":
                case "22632":
                    return "Windows 11 23H2";
                default:
                    return $"Unknown (Build {buildNumber})";
            }
        }

        private string GetWindowsVersionDetail(string ipAddress, string buildNumber)
        {
            try
            {
                string versionDetail = "Unknown";
                using (var regKey = string.IsNullOrEmpty(ipAddress) ?
                       Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion") :
                       RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ipAddress)
                                  .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (regKey != null)
                    {
                        versionDetail = regKey.GetValue("DisplayVersion")?.ToString();
                    }
                }

                if (string.IsNullOrEmpty(versionDetail))
                {
                    // Fall back to ReleaseId if DisplayVersion is not available
                    using (var regKey = string.IsNullOrEmpty(ipAddress) ?
                           Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion") :
                           RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ipAddress)
                                      .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                    {
                        versionDetail = regKey.GetValue("ReleaseId")?.ToString();
                    }
                }

                return versionDetail switch
                {
                    "21H2" => "21H2",
                    "22H2" => "22H2",
                    _ => $"Unknown (Build {buildNumber})"
                };
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Failed to get specific Windows version detail. Error: {ex.Message}", context: "GetWindowsVersionDetail");
                return $"Unknown (Build {buildNumber})";
            }
        }


        private void AddScanStatus(ScanStatus scanStatus)
        {
            Dispatcher.Invoke(() =>
            {
                lock (ScanStatuses)
                {
                    ScanStatuses.Add(scanStatus);
                }
            });
        }

        private void UpdateScanStatus(ScanStatus scanStatus)
        {
            Dispatcher.Invoke(() =>
            {
                lock (ScanStatuses)
                {
                    var index = ScanStatuses.IndexOf(scanStatus);
                    if (index != -1)
                    {
                        ScanStatuses[index] = scanStatus;
                    }
                }
            });
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            ScanStatuses.Clear();
            Logger.Log(LogLevel.INFO, "Grid data cleared by the user.");
            UpdateStatusBar("Grid cleared.");
        }


        private bool IsValidIP(string ip)
        {
            return IPAddress.TryParse(ip, out _);
        }

        private bool IsValidIPSegment(string segment)
        {
            string[] parts = segment.Split('.');
            if (parts.Length != 3) return false;
            return parts.All(part => byte.TryParse(part, out _));
        }

        private void HighlightInvalidInput(string input)
        {
            var scanStatus = new ScanStatus { IPAddress = input, Status = "Invalid", Details = "Invalid IP/Segment" };
            AddScanStatus(scanStatus);
            Logger.Log(LogLevel.WARNING, "Invalid IP/Segment input", context: "HighlightInvalidInput", additionalInfo: input);
        }

        private void ShowInvalidInputMessage()
        {
            MessageBox.Show("Invalid IP or Segment format. Please enter a valid IP or Segment.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Logger.Log(LogLevel.WARNING, "Displayed invalid input message", context: "ShowInvalidInputMessage");
        }

        private void UpdateStatusBar(string message)
        {
            Dispatcher.Invoke(() =>
            {
                StatusBarText.Text = message;
            });
        }

        private void UpdateProgressBar(int value)
        {
            Dispatcher.Invoke(() =>
            {
                ProgressBar.Value = value;
            });
        }

        private void DisableButtons()
        {
            Dispatcher.Invoke(() =>
            {
                Button1.IsEnabled = false;
                Button2.IsEnabled = false;
                Button3.IsEnabled = false;
                Button4.IsEnabled = false;
            });
        }

        private void EnableButtons()
        {
            Dispatcher.Invoke(() =>
            {
                Button1.IsEnabled = true;
                Button2.IsEnabled = true;
                Button3.IsEnabled = true;
                Button4.IsEnabled = true;
            });
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            SaveOutputFile();
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            if (cancellationTokenSource != null)
            {
                cancellationTokenSource.Cancel();
                UpdateStatusBar("Scanning stopped by user.");
                EnableButtons();
            }
        }

        private void HandleAutoSave()
        {
            if (autoSave)
            {
                SaveOutputFile();
            }
            else
            {
                ShowSavePrompt();
            }
        }

        private void ShowSavePrompt()
        {
            var result = MessageBox.Show("IP scanning is finished. Would you like to save the output?", "Save Results", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                SaveOutputFile();
            }
        }

        private void SaveOutputFile()
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv",
                Title = "Save Output File"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                outputFilePath = saveFileDialog.FileName;
                bool fileExists = File.Exists(outputFilePath);

                // Generate the header based on selected columns
                var header = string.Join(",", dataColumnSettings.Where(c => c.IsSelected).Select(c => $"\"{c.Name}\""));

                if (fileExists)
                {
                    // Read the first line of the existing file to compare with the header
                    string existingHeader = File.ReadLines(outputFilePath).FirstOrDefault();

                    if (existingHeader != header)
                    {
                        // Header doesn't match, prompt the user or overwrite file
                        var result = MessageBox.Show("The existing file has a different header. Do you want to overwrite it?", "Header Mismatch", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
                        if (result == MessageBoxResult.Cancel)
                        {
                            return;
                        }
                        else if (result == MessageBoxResult.Yes)
                        {
                            // Overwrite the file and write the new header
                            File.WriteAllText(outputFilePath, header + Environment.NewLine);
                        }
                        else if (result == MessageBoxResult.No)
                        {
                            // Append mode, write a new header only if needed
                            File.AppendAllText(outputFilePath, header + Environment.NewLine);
                        }
                    }
                }
                else
                {
                    // File does not exist, write the header
                    File.WriteAllText(outputFilePath, header + Environment.NewLine);
                }

                // Now save all the scan results
                SaveAllScanResults();
            }
        }

        private void SaveAllScanResults()
        {
            try
            {
                using (var writer = new StreamWriter(outputFilePath, true, Encoding.UTF8))
                {
                    foreach (var scanStatus in ScanStatuses)
                    {
                        var line = string.Join(",", dataColumnSettings.Where(c => c.IsSelected).Select(c =>
                        {
                            var value = GetPropertyValue(scanStatus, c.Name.Replace(" ", ""));
                            return $"\"{value}\"";
                        }));
                        writer.WriteLine(line);
                    }
                }
                MessageBox.Show("Output saved successfully.", "Save Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error saving output: {ex.Message}", context: "SaveAllScanResults");
                MessageBox.Show($"Error saving output: {ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GetPropertyValue(ScanStatus scanStatus, string propertyName)
        {
            var property = typeof(ScanStatus).GetProperty(propertyName);
            return property?.GetValue(scanStatus)?.ToString() ?? "N/A";
        }

        private void EnsureCsvFile()
        {
            try
            {
                if (!File.Exists(outputFilePath))
                {
                    var header = string.Join(",", dataColumnSettings.Where(c => c.IsSelected).Select(c => $"\"{c.Name}\""));
                    File.WriteAllText(outputFilePath, header + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error ensuring CSV file: {ex.Message}", context: "EnsureCsvFile");
                MessageBox.Show($"Error ensuring CSV file: {ex.Message}", "File Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class ScanStatus
    {
        public string IPAddress { get; set; }
        public string Hostname { get; set; }
        public string LastLoggedUser { get; set; }
        public string MachineType { get; set; }
        public string MachineSKU { get; set; }
        public string InstalledCoreSoftware { get; set; }
        public string RAMSize { get; set; }
        public string WindowsVersion { get; set; }
        public string WindowsRelease { get; set; }
        public string MicrosoftOfficeVersion { get; set; } // New Property
        public string Date { get; set; }
        public string Time { get; set; }
        public string Status { get; set; }
        public string Details { get; set; }

        public ScanStatus()
        {
            IPAddress = "";
            Hostname = "N/A";
            LastLoggedUser = "N/A";
            MachineType = "N/A";
            MachineSKU = "N/A";
            InstalledCoreSoftware = "N/A";
            RAMSize = "N/A";
            WindowsVersion = "N/A";
            WindowsRelease = "N/A";
            MicrosoftOfficeVersion = "N/A"; // Initialize New Property
            Date = DateTime.Now.ToString("M/dd/yyyy");
            Time = DateTime.Now.ToString("HH:mm");
            Status = "Not Started";
            Details = "N/A";
        }
    }

}