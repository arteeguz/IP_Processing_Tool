using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using System.ComponentModel;
using System.Windows.Data;

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
        private int pingTimeout = 1000; // Default value in milliseconds
        private Dictionary<string, string> floorMappings;
        private int totalIPs;
        private int processedIPs;
        private int MaxConcurrentScans = Environment.ProcessorCount; // Default to number of processor cores
        private int ExecutionTimeLimit = 60; // Default to 60 seconds
        private ICollectionView _scanView;
        private string _filterText = string.Empty;

        public MainWindow()
        {
            InitializeComponent();
            ScanStatuses = new ObservableCollection<ScanStatus>();
            _scanView = CollectionViewSource.GetDefaultView(ScanStatuses);
            _scanView.Filter = FilterRow;
            StatusDataGrid.ItemsSource = _scanView;

            parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            InitializeFloorMappings();
            InitializeColumnSettings();
            LoadPersistedSettings();
            UpdateDataGridColumns();

            Logger.Log(LogLevel.INFO, "Application started");
        }

        private void LoadPersistedSettings()
        {
            var saved = AppSettings.Load();
            if (saved.PingTimeout > 0) pingTimeout = saved.PingTimeout;
            if (saved.MaxConcurrentScans > 0) MaxConcurrentScans = saved.MaxConcurrentScans;
            if (saved.ExecutionTimeLimit > 0) ExecutionTimeLimit = saved.ExecutionTimeLimit;
            autoSave = saved.AutoSave;

            // Restore column visibility if saved, otherwise keep defaults
            if (saved.Columns != null && saved.Columns.Count > 0)
            {
                foreach (var savedCol in saved.Columns)
                {
                    var match = dataColumnSettings.FirstOrDefault(c => c.PropertyName == savedCol.PropertyName);
                    if (match != null) match.IsSelected = savedCol.IsSelected;
                }
            }
        }

        private void SavePersistedSettings()
        {
            var settings = new AppSettings
            {
                PingTimeout = pingTimeout,
                MaxConcurrentScans = MaxConcurrentScans,
                ExecutionTimeLimit = ExecutionTimeLimit,
                AutoSave = autoSave,
                Columns = dataColumnSettings.Select(c => new ColumnSettingData
                {
                    Name = c.Name,
                    PropertyName = c.PropertyName,
                    IsSelected = c.IsSelected
                }).ToList()
            };
            settings.Save();
        }

        private void InitializeColumnSettings()
        {
            dataColumnSettings = new ObservableCollection<ColumnSetting>
            {
                new ColumnSetting { Name = "IP Address",                   PropertyName = nameof(ScanStatus.IPAddress),               IsSelected = true  },
                new ColumnSetting { Name = "Hostname",                     PropertyName = nameof(ScanStatus.Hostname),                IsSelected = true  },
                new ColumnSetting { Name = "Last Logged User",             PropertyName = nameof(ScanStatus.LastLoggedUser),          IsSelected = true  },
                new ColumnSetting { Name = "Machine Model",                PropertyName = nameof(ScanStatus.MachineModel),            IsSelected = true  },
                new ColumnSetting { Name = "Disk Size",                    PropertyName = nameof(ScanStatus.DiskSize),                IsSelected = true  },
                new ColumnSetting { Name = "Disk Free Space",              PropertyName = nameof(ScanStatus.DiskFreeSpace),           IsSelected = true  },
                new ColumnSetting { Name = "Other Drives",                 PropertyName = nameof(ScanStatus.OtherDrives),             IsSelected = true  },
                new ColumnSetting { Name = "RAM Size",                     PropertyName = nameof(ScanStatus.RAMSize),                 IsSelected = true  },
                new ColumnSetting { Name = "Windows Info",                 PropertyName = nameof(ScanStatus.WindowsInfo),             IsSelected = true  },
                new ColumnSetting { Name = "Microsoft Office Version",     PropertyName = nameof(ScanStatus.MicrosoftOfficeVersion),  IsSelected = true  },
                new ColumnSetting { Name = "BIOS Version Date",            PropertyName = nameof(ScanStatus.BIOSVersionDate),         IsSelected = true  },
                new ColumnSetting { Name = "SMBIOS Version",               PropertyName = nameof(ScanStatus.SMBIOSVersion),           IsSelected = true  },
                new ColumnSetting { Name = "Embedded Controller Version",  PropertyName = nameof(ScanStatus.EmbeddedControllerVersion), IsSelected = true },
                new ColumnSetting { Name = "MAC Address",                  PropertyName = nameof(ScanStatus.MACAddress),              IsSelected = true  },
                new ColumnSetting { Name = "NIC 0 LAN",                    PropertyName = nameof(ScanStatus.NIC0LAN),                 IsSelected = true  },
                new ColumnSetting { Name = "NIC 1 WiFi",                   PropertyName = nameof(ScanStatus.NIC1WiFi),                IsSelected = true  },
                new ColumnSetting { Name = "NIC 2 LAN 2",                  PropertyName = nameof(ScanStatus.NIC2LAN2),                IsSelected = true  },
                new ColumnSetting { Name = "NIC 3",                        PropertyName = nameof(ScanStatus.NIC3),                   IsSelected = false },
                new ColumnSetting { Name = "Date",                         PropertyName = nameof(ScanStatus.Date),                   IsSelected = true  },
                new ColumnSetting { Name = "Time",                         PropertyName = nameof(ScanStatus.Time),                   IsSelected = true  },
                new ColumnSetting { Name = "Ping Time",                    PropertyName = nameof(ScanStatus.PingTime),               IsSelected = true  },
                new ColumnSetting { Name = "Status",                       PropertyName = nameof(ScanStatus.Status),                 IsSelected = true  },
                new ColumnSetting { Name = "Details",                      PropertyName = nameof(ScanStatus.Details),                IsSelected = true  },
                new ColumnSetting { Name = "Port 16992",                   PropertyName = nameof(ScanStatus.Port16992),              IsSelected = true  },
                new ColumnSetting { Name = "Port 16993",                   PropertyName = nameof(ScanStatus.Port16993),              IsSelected = true  },
                new ColumnSetting { Name = "Port 22",                      PropertyName = nameof(ScanStatus.Port22),                 IsSelected = false },
                new ColumnSetting { Name = "Port 80",                      PropertyName = nameof(ScanStatus.Port80),                 IsSelected = false },
                new ColumnSetting { Name = "Port 443",                     PropertyName = nameof(ScanStatus.Port443),                IsSelected = false },
                new ColumnSetting { Name = "Port 3389",                    PropertyName = nameof(ScanStatus.Port3389),               IsSelected = false },
                new ColumnSetting { Name = "Port 5985",                    PropertyName = nameof(ScanStatus.Port5985),               IsSelected = false },
                new ColumnSetting { Name = "Floor",                        PropertyName = nameof(ScanStatus.Floor),                  IsSelected = true  },
            };
        }

        private void UpdateDataGridColumns()
        {
            StatusDataGrid.Columns.Clear();
            foreach (var column in dataColumnSettings.Where(c => c.IsSelected))
            {
                var binding = column.Name == "Ping Time"
                    ? new Binding(column.PropertyName) { StringFormat = "{0} ms" }
                    : new Binding(column.PropertyName);

                StatusDataGrid.Columns.Add(new DataGridTextColumn
                {
                    Header = column.Name,
                    Binding = binding,
                    SortMemberPath = column.PropertyName   // enables column-header click sorting
                });
            }
            _scanView?.Refresh();
            UpdateResultCount();
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new Settings(dataColumnSettings, autoSave, pingTimeout, MaxConcurrentScans, ExecutionTimeLimit);
            if (settingsWindow.ShowDialog() == true)
            {
                dataColumnSettings = new ObservableCollection<ColumnSetting>(settingsWindow.DataColumns);
                autoSave = settingsWindow.AutoSave;
                pingTimeout = settingsWindow.PingTimeout;
                MaxConcurrentScans = settingsWindow.MaxConcurrentScans;
                ExecutionTimeLimit = settingsWindow.ExecutionTimeLimit;

                SavePersistedSettings();
                UpdateDataGridColumns();

                if (settingsWindow.DataRetrievalOptionsChanged && ScanStatuses.Count > 0)
                {
                    var result = MessageBox.Show("Data retrieval options have changed. Would you like to rescan the previously scanned IP addresses?",
                        "Rescan Confirmation", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result == MessageBoxResult.Yes)
                    {
                        RescanPreviousIPs();
                    }
                }
            }
        }

        // update code (replace 4 button handlers with single modern scan handler)
        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            var inputWindow = new ModernInputWindow();
            if (inputWindow.ShowDialog() == true)
            {
                var targets = inputWindow.ProcessedTargets;
                Logger.Log(LogLevel.INFO, "User started scan with modern input", context: "ScanButton_Click",
                    additionalInfo: $"{targets.Count} targets");
                await ProcessIPsAsync(targets);
            }
        }
        // end of update

        private async Task ProcessIPsAsync(IEnumerable<string> ipsOrHostnames)
        {
            var resolvedIPs = new List<(string original, string resolved)>();

            // Resolve all hostnames to IPs in parallel — avoids sequential DNS delay
            UpdateStatusBar("Resolving hostnames...");
            var entries = ipsOrHostnames.ToList();
            var resolutionTasks = entries.Select(e => ResolveHostnameToIPAsync(e)).ToList();
            var resolutionResults = await Task.WhenAll(resolutionTasks);

            for (int i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                var resolvedIP = resolutionResults[i];
                if (!string.IsNullOrEmpty(resolvedIP))
                {
                    resolvedIPs.Add((entry, resolvedIP));
                }
                else
                {
                    var failedStatus = new ScanStatus
                    {
                        IPAddress = entry,
                        Hostname = entry,
                        Status = "Resolution Failed",
                        Details = "Could not resolve hostname to IP address",
                        Date = DateTime.Now.ToString("M/dd/yyyy"),
                        Time = DateTime.Now.ToString("HH:mm:ss")
                    };
                    UpdateScanStatus(failedStatus);
                }
            }

            totalIPs = resolvedIPs.Count;
            processedIPs = 0;
            UpdateProgressBar(0, 0, totalIPs);

            DisableButtons();

            cancellationTokenSource = new CancellationTokenSource();
            var semaphore = new SemaphoreSlim(MaxConcurrentScans);

            try
            {
                var tasks = new List<Task>();
                foreach (var (original, resolved) in resolvedIPs)
                {
                    await semaphore.WaitAsync(cancellationTokenSource.Token);
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            var scanStatus = await ProcessIPAsync(resolved, cancellationTokenSource.Token);
                            if (scanStatus != null)
                            {
                                // If we resolved a hostname, update the hostname field
                                if (original != resolved && !IPAddress.TryParse(original, out _))
                                {
                                    scanStatus.Hostname = original;
                                }
                                UpdateScanStatus(scanStatus);
                            }
                            int done = Interlocked.Increment(ref processedIPs);
                            UpdateProgressBar((int)((double)done / totalIPs * 100), done, totalIPs);
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, cancellationTokenSource.Token));
                }

                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                Logger.Log(LogLevel.INFO, "Scan operation was cancelled", context: "ProcessIPsAsync");
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, "Error processing IPs", context: "ProcessIPsAsync", additionalInfo: ex.Message);
                MessageBox.Show($"An error occurred while processing IPs: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                EnableButtons();
                UpdateScanSummary();
                UpdateProgressBar(100, totalIPs, totalIPs);
                HandleAutoSave();
            }
        }

        private async Task<string> ResolveHostnameToIPAsync(string hostnameOrIP)
        {
            try
            {
                // First check if it's already an IP address
                if (IPAddress.TryParse(hostnameOrIP, out _))
                {
                    return hostnameOrIP;
                }

                // Try to resolve hostname to IP
                var hostEntry = await Dns.GetHostEntryAsync(hostnameOrIP);

                // Get the first IPv4 address
                var ipv4 = hostEntry.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
                if (ipv4 != null)
                {
                    return ipv4.ToString();
                }

                // If no IPv4, try IPv6
                var ipv6 = hostEntry.AddressList.FirstOrDefault();
                if (ipv6 != null)
                {
                    return ipv6.ToString();
                }

                Logger.Log(LogLevel.WARNING, $"No IP addresses found for hostname: {hostnameOrIP}", context: "ResolveHostnameToIPAsync");
                return null;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Failed to resolve hostname '{hostnameOrIP}': {ex.Message}", context: "ResolveHostnameToIPAsync");
                return null;
            }
        }

        private async void RescanPreviousIPs()
        {
            var ips = ScanStatuses.Select(s => s.IPAddress).ToList();
            ScanStatuses.Clear();
            await ProcessIPsAsync(ips);
        }

        private void RescanButton_Click(object sender, RoutedEventArgs e)
        {
            if (ScanStatuses.Count > 0)
            {
                RescanPreviousIPs();
            }
            else
            {
                MessageBox.Show("No previous scan data available. Please perform a scan first.", "No Data", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private async void WakeOnLANButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = StatusDataGrid.SelectedItems.Cast<ScanStatus>().ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("Please select at least one IP address to wake.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var scanStatus in selectedItems)
            {
                if (!string.IsNullOrEmpty(scanStatus.MACAddress))
                {
                    try
                    {
                        await WOL.WakeOnLan(scanStatus.MACAddress);
                        Logger.Log(LogLevel.INFO, $"Wake-on-LAN packet sent to {scanStatus.IPAddress} (MAC: {scanStatus.MACAddress})", context: "WakeOnLAN");
                    }
                    catch (Exception ex)
                    {
                        Logger.Log(LogLevel.ERROR, $"Error sending Wake-on-LAN packet to {scanStatus.IPAddress}: {ex.Message}", context: "WakeOnLAN");
                    }
                }
                else
                {
                    Logger.Log(LogLevel.WARNING, $"MAC address not found for IP {scanStatus.IPAddress}", context: "WakeOnLAN");
                }
            }

            MessageBox.Show("Wake-on-LAN packets sent to selected IP addresses.", "Wake-on-LAN", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async Task<ScanStatus> ProcessIPAsync(string ip, CancellationToken cancellationToken)
        {
            var scanStatus = new ScanStatus
            {
                IPAddress = ip,
                Status = "Processing",
                Details = "",
                Date = DateTime.Now.ToString("M/dd/yyyy"),
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Floor = dataColumnSettings.Any(c => c.IsSelected && c.Name == "Floor") ? GetFloorForIP(ip) : "N/A"
            };

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(ExecutionTimeLimit));

                await ProcessIPInternalAsync(ip, scanStatus, cts.Token);
            }
            catch (OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    scanStatus.Status = "Cancelled";
                    scanStatus.Details = "Operation canceled by user";
                }
                else
                {
                    scanStatus.Status = "Timeout";
                    scanStatus.Details = "Operation timed out";
                }
            }
            catch (Exception ex)
            {
                scanStatus.Status = "Error";
                scanStatus.Details = $"Unexpected error: {ex.Message}";
                Logger.Log(LogLevel.ERROR, $"Unexpected error processing IP {ip}: {ex.Message}", context: "ProcessIPAsync");
            }

            return scanStatus;
        }

        private async Task ProcessIPInternalAsync(string ip, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();

            try
            {
                var (pingSuccess, pingTime) = await PingHostAsync(ip, cancellationToken);

                scanStatus.PingTime = pingSuccess ? pingTime : -1;

                if (pingSuccess)
                {
                    scanStatus.Status = "Reachable";

                    try
                    {
                        ConnectionOptions options = new ConnectionOptions
                        {
                            Impersonation = ImpersonationLevel.Impersonate,
                            EnablePrivileges = true,
                            Authentication = AuthenticationLevel.PacketPrivacy
                        };

                        var scope = new ManagementScope($"\\\\{ip}\\root\\cimv2", options);
                        try
                        {
                            await Task.Run(() => scope.Connect(), cancellationToken);

                            var tasks = new List<Task>();

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Hostname"))
                            {
                                tasks.Add(GetHostnameAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Machine Model"))
                            {
                                tasks.Add(GetMachineModelAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Last Logged User"))
                            {
                                tasks.Add(GetLastLoggedUserAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "RAM Size"))
                            {
                                tasks.Add(GetRAMSizeAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Windows Info"))
                            {
                                tasks.Add(GetWindowsInfoAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "Microsoft Office Version"))
                            {
                                tasks.Add(GetOfficeVersionAsync(ip, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && (c.Name == "Disk Size" || c.Name == "Disk Free Space" || c.Name == "Other Drives")))
                            {
                                tasks.Add(GetDiskInfoAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && (c.Name == "BIOS Version Date" || c.Name == "SMBIOS Version" || c.Name == "Embedded Controller Version")))
                            {
                                tasks.Add(GetBIOSInfoAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && (c.Name == "NIC 0 LAN" || c.Name == "NIC 1 WiFi" || c.Name == "NIC 2 LAN 2" || c.Name == "NIC 3" || c.Name == "MAC Address")))
                            {
                                tasks.Add(GetNetworkAdaptersInfoAsync(scope, scanStatus, cancellationToken));
                            }

                            if (dataColumnSettings.Any(c => c.IsSelected && c.Name.StartsWith("Port ")))
                            {
                                tasks.Add(CheckPortsAsync(ip, scanStatus, cancellationToken));
                            }

                            await Task.WhenAll(tasks);

                            scanStatus.Status = "Complete";
                        }
                        catch (System.IO.IOException ioEx)
                        {
                            Logger.Log(LogLevel.WARNING, $"Network error for IP {ip}: {ioEx.Message}", context: "ProcessIPInternalAsync");
                            scanStatus.Status = "Network Error";
                            scanStatus.Details = $"Network error: Please check connectivity and Remote Registry service. {ioEx.Message}";
                        }
                        catch (System.UnauthorizedAccessException uaEx)
                        {
                            Logger.Log(LogLevel.WARNING, $"Access denied for IP {ip}: {uaEx.Message}", context: "ProcessIPInternalAsync");
                            scanStatus.Status = "Access Denied";
                            scanStatus.Details = $"Access denied: Please check permissions. {uaEx.Message}";
                        }
                        catch (Exception ex)
                        {
                            Logger.Log(LogLevel.ERROR, $"Error processing IP {ip}: {ex.Message}", context: "ProcessIPInternalAsync");
                            scanStatus.Status = "Error";
                            scanStatus.Details = $"Error: {ex.Message}";
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Log(LogLevel.ERROR, $"Unexpected error for IP {ip}: {ex.Message}", context: "ProcessIPInternalAsync");
                        scanStatus.Status = "Unexpected Error";
                        scanStatus.Details = $"Unexpected error: {ex.Message}";
                    }
                }
                else
                {
                    scanStatus.Status = "Not Reachable";
                    scanStatus.Details = "Host not reachable";
                    Logger.Log(LogLevel.WARNING, $"Host not reachable for IP {ip}", context: "ProcessIPInternalAsync");
                }
            }
            catch (OperationCanceledException)
            {
                scanStatus.Status = "Cancelled";
                scanStatus.Details = "Operation was cancelled";
                Logger.Log(LogLevel.INFO, $"Operation cancelled for IP {ip}", context: "ProcessIPInternalAsync");
            }
            catch (Exception ex)
            {
                scanStatus.Status = "Fatal Error";
                scanStatus.Details = $"A fatal error occurred: {ex.Message}";
                Logger.Log(LogLevel.ERROR, $"Fatal error processing IP {ip}: {ex.Message}", context: "ProcessIPInternalAsync");
            }
            finally
            {
                stopwatch.Stop();
                scanStatus.Details += $" Total processing time: {stopwatch.ElapsedMilliseconds} ms";

                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        private async Task GetMachineModelAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            // Win32_ComputerSystemProduct.Version is often blank or "None" on modern hardware.
            // Win32_ComputerSystem.Manufacturer + Model reliably returns e.g. "HP EliteBook 840 G9".
            try
            {
                var modelQuery = new ObjectQuery("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
                using var modelSearcher = new ManagementObjectSearcher(scope, modelQuery);
                var model = await Task.Run(() => modelSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                if (model != null)
                {
                    string manufacturer = model["Manufacturer"]?.ToString()?.Trim() ?? "";
                    string modelName = model["Model"]?.ToString()?.Trim() ?? "";
                    scanStatus.MachineModel = string.IsNullOrEmpty(manufacturer)
                        ? modelName
                        : $"{manufacturer} {modelName}".Trim();
                    if (string.IsNullOrEmpty(scanStatus.MachineModel))
                        scanStatus.MachineModel = "N/A";
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting machine model: {ex.Message}", context: "GetMachineModelAsync");
            }
        }

        private async Task GetHostnameAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var hostnameQuery = new ObjectQuery("SELECT Name FROM Win32_ComputerSystem");
                using (var hostnameSearcher = new ManagementObjectSearcher(scope, hostnameQuery))
                {
                    var computer = await Task.Run(() => hostnameSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                    if (computer != null)
                    {
                        scanStatus.Hostname = computer["Name"]?.ToString() ?? "N/A";
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting hostname: {ex.Message}", context: "GetHostnameAsync");
            }
        }

        private async Task GetBIOSInfoAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                // Single query fetches all BIOS fields — avoids 3 separate WMI round trips
                var biosQuery = new ObjectQuery(
                    "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, " +
                    "SMBIOSMajorVersion, SMBIOSMinorVersion, " +
                    "EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion " +
                    "FROM Win32_BIOS");
                using var biosSearcher = new ManagementObjectSearcher(scope, biosQuery);
                var bios = await Task.Run(() => biosSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);

                if (bios != null)
                {
                    // BIOS version + date
                    string manufacturer = bios["Manufacturer"]?.ToString() ?? "Unknown";
                    string smbiosBiosVersion = bios["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown";
                    string releaseDate = bios["ReleaseDate"]?.ToString() ?? "Unknown";
                    if (releaseDate != "Unknown" && DateTime.TryParseExact(
                            releaseDate.Split('.')[0], "yyyyMMddHHmmss",
                            CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime parsedDate))
                    {
                        releaseDate = parsedDate.ToString("M/d/yyyy");
                    }
                    scanStatus.BIOSVersionDate = $"{manufacturer}, {smbiosBiosVersion}, {releaseDate}";

                    // SMBIOS version
                    int smbiosMajor = Convert.ToInt32(bios["SMBIOSMajorVersion"]);
                    int smbiosMinor = Convert.ToInt32(bios["SMBIOSMinorVersion"]);
                    scanStatus.SMBIOSVersion = $"{smbiosMajor}.{smbiosMinor}";

                    // Embedded Controller version — 255.255 means virtual machine / not present
                    int ecMajor = Convert.ToInt32(bios["EmbeddedControllerMajorVersion"]);
                    int ecMinor = Convert.ToInt32(bios["EmbeddedControllerMinorVersion"]);
                    scanStatus.EmbeddedControllerVersion = (ecMajor == 255 && ecMinor == 255)
                        ? "N/A (Virtual)"
                        : $"{ecMajor}.{ecMinor}";
                }
                else
                {
                    scanStatus.BIOSVersionDate = "BIOS information not available";
                    scanStatus.SMBIOSVersion = "N/A";
                    scanStatus.EmbeddedControllerVersion = "N/A";
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting BIOS info: {ex.Message}", context: "GetBIOSInfoAsync");
                scanStatus.BIOSVersionDate = "Error retrieving BIOS information";
                scanStatus.SMBIOSVersion = "Error";
                scanStatus.EmbeddedControllerVersion = "Error";
            }
        }

        private async Task GetLastLoggedUserAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            // Win32_ComputerSystem.UserName only returns the currently interactive user and is
            // null when nobody is logged in. The registry key persists the last logged-on user
            // even after logoff, making it the correct source for this field.
            await Task.Run(() =>
            {
                try
                {
                    using var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, scope.Path.Server);
                    using var key = baseKey.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
                    scanStatus.LastLoggedUser = key?.GetValue("LastLoggedOnUser") as string ?? "N/A";
                }
                catch (Exception ex)
                {
                    Logger.Log(LogLevel.ERROR, $"Error getting last logged user: {ex.Message}", context: "GetLastLoggedUserAsync");
                    scanStatus.LastLoggedUser = "N/A";
                }
            }, cancellationToken);
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
                var osQuery = new ObjectQuery("SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem");
                using var osSearcher = new ManagementObjectSearcher(scope, osQuery);
                var os = await Task.Run(() => osSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                if (os != null)
                {
                    string caption = os["Caption"]?.ToString() ?? "Unknown Windows";
                    string buildNumber = os["BuildNumber"]?.ToString() ?? "Unknown";
                    string version = os["Version"]?.ToString() ?? "Unknown";

                    string windowsEdition = GetWindowsEdition(caption);
                    string releaseId = await GetWindowsReleaseIdAsync(scope, cancellationToken);

                    scanStatus.WindowsInfo = $"{windowsEdition} {releaseId}";
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting Windows info: {ex.Message}", context: "GetWindowsInfoAsync");
                scanStatus.WindowsInfo = "Error retrieving Windows info";
            }
        }

        private string GetWindowsEdition(string caption)
        {
            if (caption.Contains("Windows 10"))
                return "Windows 10";
            else if (caption.Contains("Windows 11"))
                return "Windows 11";
            else
                return caption;
        }

        private async Task<string> GetWindowsReleaseIdAsync(ManagementScope scope, CancellationToken cancellationToken)
        {
            return await Task.Run(() =>
            {
                try
                {
                    using var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, scope.Path.Server);
                    using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                    if (key == null) return "Unknown";

                    // DisplayVersion is correct on Windows 10 20H2+ and all Windows 11 (e.g. "23H2")
                    // ReleaseId is frozen at "2009" on Windows 11 — only used as legacy fallback
                    return key.GetValue("DisplayVersion") as string
                        ?? key.GetValue("ReleaseId") as string
                        ?? "Unknown";
                }
                catch (Exception ex)
                {
                    Logger.Log(LogLevel.ERROR, $"Error getting Windows release ID: {ex.Message}", context: "GetWindowsReleaseIdAsync");
                    return "Unknown";
                }
            }, cancellationToken);
        }

        private async Task GetOfficeVersionAsync(string machineName, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            string officeVersion = "Not Installed";
            string[] officeKeywords = new[] { "Microsoft Office", "Office 365", "Microsoft 365" };

            // Check both 64-bit and 32-bit (WOW6432Node) uninstall paths.
            // Microsoft 365 64-bit installs under the standard path; legacy 32-bit Office installs
            // under WOW6432Node on a 64-bit OS.
            string[] registryPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            try
            {
                await Task.Run(() =>
                {
                    try
                    {
                        using RegistryKey baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machineName);
                        foreach (string registryPath in registryPaths)
                        {
                            if (officeVersion != "Not Installed") break;

                            using RegistryKey uninstallKey = baseKey.OpenSubKey(registryPath);
                            if (uninstallKey == null) continue;

                            foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                            {
                                cancellationToken.ThrowIfCancellationRequested();

                                using RegistryKey officeKey = uninstallKey.OpenSubKey(subKeyName);
                                if (officeKey == null) continue;

                                string displayName = officeKey.GetValue("DisplayName") as string;
                                string displayVersion = officeKey.GetValue("DisplayVersion") as string;

                                if (!string.IsNullOrEmpty(displayName) && !string.IsNullOrEmpty(displayVersion) &&
                                    officeKeywords.Any(kw => displayName.Contains(kw, StringComparison.OrdinalIgnoreCase)) &&
                                    !displayName.Contains("Runtime", StringComparison.OrdinalIgnoreCase) &&
                                    !displayName.Contains("Tools", StringComparison.OrdinalIgnoreCase))
                                {
                                    officeVersion = $"{displayName} ({displayVersion})";
                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        Logger.Log(LogLevel.ERROR, $"Error accessing registry for {machineName}: {ex.Message}", context: "GetOfficeVersionAsync");
                        officeVersion = "Error accessing registry";
                    }
                }, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                officeVersion = "Operation Cancelled";
            }

            scanStatus.MicrosoftOfficeVersion = officeVersion;
        }

        private async Task<(bool success, long roundTripTime)> PingHostAsync(string ip, CancellationToken cancellationToken)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(ip, pingTimeout);
                    return (reply.Status == IPStatus.Success, reply.RoundtripTime);
                }
            }
            catch (OperationCanceledException)
            {
                Logger.Log(LogLevel.INFO, $"Ping operation cancelled for IP {ip}", context: "PingHostAsync");
                throw;
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Ping exception for IP {ip}", context: "PingHostAsync", additionalInfo: ex.Message);
                return (false, -1);
            }
        }


        private async Task<string> GetMACAddressAsync(string ipAddress, CancellationToken cancellationToken)
        {
            try
            {
                IPAddress ip = IPAddress.Parse(ipAddress);
                byte[] macAddr = new byte[6];
                uint macAddrLen = (uint)macAddr.Length;

                if (SendARP((int)ip.Address, 0, macAddr, ref macAddrLen) != 0)
                {
                    return "Not Available";
                }

                string[] str = new string[(int)macAddrLen];
                for (int i = 0; i < macAddrLen; i++)
                    str[i] = macAddr[i].ToString("x2");
                return string.Join(":", str);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting MAC address: {ex.Message}", context: "GetMACAddressAsync");
                return "Error";
            }
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIP, int srcIP, byte[] macAddr, ref uint physicalAddrLen);

        private async Task GetDiskInfoAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var diskQuery = new ObjectQuery("SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3");
                using var diskSearcher = new ManagementObjectSearcher(scope, diskQuery);
                var disks = await Task.Run(() => diskSearcher.Get().Cast<ManagementObject>().ToList(), cancellationToken);

                if (disks.Any())
                {
                    var cDrive = disks.FirstOrDefault(d => d["DeviceID"].ToString().Equals("C:", StringComparison.OrdinalIgnoreCase));
                    var otherDrives = disks.Where(d => !d["DeviceID"].ToString().Equals("C:", StringComparison.OrdinalIgnoreCase)).ToList();

                    if (cDrive != null)
                    {
                        double size = Convert.ToDouble(cDrive["Size"]);
                        double freeSpace = Convert.ToDouble(cDrive["FreeSpace"]);
                        double usedSpace = size - freeSpace;
                        double usedPercentage = (usedSpace / size) * 100;
                        double freePercentage = 100 - usedPercentage;

                        scanStatus.DiskSize = $"C: {size / (1024 * 1024 * 1024):F2} GB";
                        scanStatus.DiskFreeSpace = $"C: {freePercentage:F2}% ({freeSpace / (1024 * 1024 * 1024):F2} GB)";
                    }
                    else
                    {
                        scanStatus.DiskSize = "C: Not found";
                        scanStatus.DiskFreeSpace = "C: N/A";
                    }

                    if (otherDrives.Any())
                    {
                        var otherDrivesInfo = new List<string>();
                        foreach (var drive in otherDrives)
                        {
                            string deviceID = drive["DeviceID"].ToString();
                            double size = Convert.ToDouble(drive["Size"]);
                            double freeSpace = Convert.ToDouble(drive["FreeSpace"]);
                            double freePercentage = (freeSpace / size) * 100;

                            otherDrivesInfo.Add($"{deviceID}: {size / (1024 * 1024 * 1024):F2} GB, {freePercentage:F2}% free");
                        }
                        scanStatus.OtherDrives = string.Join(" | ", otherDrivesInfo);
                    }
                    else
                    {
                        scanStatus.OtherDrives = "No other drives";
                    }
                }
                else
                {
                    scanStatus.DiskSize = "No disks found";
                    scanStatus.DiskFreeSpace = "N/A";
                    scanStatus.OtherDrives = "N/A";
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting disk info: {ex.Message}", context: "GetDiskInfoAsync");
                scanStatus.DiskSize = "Error";
                scanStatus.DiskFreeSpace = "Error";
                scanStatus.OtherDrives = "Error";
            }
        }

        private async Task GetNetworkAdaptersInfoAsync(ManagementScope scope, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                // ── Step 1: build IP-address lookup from adapter configurations ───────────
                // Query only IP-enabled configs to get IP addresses per adapter index.
                var ipLookup = new Dictionary<uint, string>();
                try
                {
                    var cfgQuery = new ObjectQuery(
                        "SELECT Index, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True");
                    using var cfgSearcher = new ManagementObjectSearcher(scope, cfgQuery);
                    var configs = await Task.Run(() => cfgSearcher.Get().Cast<ManagementObject>().ToList(), cancellationToken);
                    foreach (var cfg in configs)
                    {
                        uint idx = Convert.ToUInt32(cfg["Index"]);
                        var ips = cfg["IPAddress"] as string[];
                        // Take the first IPv4 address
                        string ipv4 = ips?.FirstOrDefault(ip => !ip.Contains(':')) ?? "";
                        if (!string.IsNullOrEmpty(ipv4))
                            ipLookup[idx] = ipv4;
                    }
                }
                catch { /* non-fatal: IP info is optional */ }

                // ── Step 2: query physical non-Microsoft adapters ─────────────────────────
                // AdapterTypeId: 0=Ethernet 802.3, 9=Wireless 802.11, 15=Wireless WAN
                // We do NOT filter on NetEnabled — an adapter can be physically present but
                // currently disconnected (e.g. docked LAN unplugged, WiFi off).
                var adapterQuery = new ObjectQuery(
                    "SELECT DeviceID, Index, Name, AdapterTypeId, MACAddress, NetEnabled, Speed " +
                    "FROM Win32_NetworkAdapter " +
                    "WHERE PhysicalAdapter=True AND Manufacturer != 'Microsoft'");
                using var searcher = new ManagementObjectSearcher(scope, adapterQuery);
                var adapters = await Task.Run(
                    () => searcher.Get().Cast<ManagementObject>().ToList(), cancellationToken);

                // ── Step 3: classify each adapter ────────────────────────────────────────
                // Sort so Ethernet adapters come first (consistent NIC0/NIC2 assignment).
                var classified = adapters
                    .Select(a =>
                    {
                        uint typeId = a["AdapterTypeId"] != null ? Convert.ToUInt32(a["AdapterTypeId"]) : 99u;
                        string name = a["Name"]?.ToString() ?? "Unknown";
                        // WiFi: AdapterTypeId 9 or 15, OR name contains wireless keywords
                        bool isWifi = typeId == 9 || typeId == 15
                            || name.Contains("Wi-Fi",    StringComparison.OrdinalIgnoreCase)
                            || name.Contains("WiFi",     StringComparison.OrdinalIgnoreCase)
                            || name.Contains("Wireless", StringComparison.OrdinalIgnoreCase)
                            || name.Contains("WLAN",     StringComparison.OrdinalIgnoreCase)
                            || name.Contains("802.11",   StringComparison.OrdinalIgnoreCase);
                        bool isEthernet = !isWifi && (typeId == 0
                            || name.Contains("Ethernet", StringComparison.OrdinalIgnoreCase)
                            || name.Contains("LAN",      StringComparison.OrdinalIgnoreCase));
                        return (adapter: a, name, typeId, isWifi, isEthernet);
                    })
                    // Ethernet first, then WiFi, then others
                    .OrderBy(x => x.isEthernet ? 0 : x.isWifi ? 1 : 2)
                    .ToList();

                // ── Step 4: fill NIC slots ────────────────────────────────────────────────
                bool macSet  = false;
                bool nic0Set = false;
                bool nic1Set = false;
                bool nic2Set = false;
                bool nic3Set = false;

                foreach (var (adapter, name, typeId, isWifi, isEthernet) in classified)
                {
                    string mac      = adapter["MACAddress"]?.ToString() ?? "";
                    bool connected  = adapter["NetEnabled"] != null && Convert.ToBoolean(adapter["NetEnabled"]);
                    uint index      = adapter["Index"] != null ? Convert.ToUInt32(adapter["Index"]) : uint.MaxValue;
                    string speedRaw = adapter["Speed"] != null
                        ? $"{Convert.ToInt64(adapter["Speed"]) / 1_000_000} Mbps"
                        : "—";
                    string ip       = ipLookup.TryGetValue(index, out var foundIp) ? foundIp : "";
                    string status   = connected ? "Connected" : "Disconnected";
                    string detail   = string.IsNullOrEmpty(ip)
                        ? $"{name} | MAC: {mac} | {speedRaw} | {status}"
                        : $"{name} | MAC: {mac} | IP: {ip} | {speedRaw} | {status}";

                    // MAC: prefer Ethernet, fall back to any
                    if (!macSet && !string.IsNullOrEmpty(mac))
                    {
                        if (isEthernet || !classified.Any(x => x.isEthernet && !string.IsNullOrEmpty(x.adapter["MACAddress"]?.ToString())))
                        {
                            scanStatus.MACAddress = mac;
                            macSet = true;
                        }
                    }

                    if (isEthernet)
                    {
                        if (!nic0Set) { scanStatus.NIC0LAN  = detail; nic0Set = true; }
                        else if (!nic2Set) { scanStatus.NIC2LAN2 = detail; nic2Set = true; }
                        else if (!nic3Set) { scanStatus.NIC3     = detail; nic3Set = true; }
                    }
                    else if (isWifi)
                    {
                        if (!nic1Set) { scanStatus.NIC1WiFi = detail; nic1Set = true; }
                        else if (!nic3Set) { scanStatus.NIC3    = detail; nic3Set = true; }
                    }
                    else
                    {
                        // Other physical adapter (e.g. Bluetooth PAN, LTE)
                        if (!nic3Set) { scanStatus.NIC3 = detail; nic3Set = true; }
                    }

                    if (macSet && nic0Set && nic1Set && nic2Set && nic3Set) break;
                }

                // Ensure MAC is set if we skipped the Ethernet-preference logic
                if (!macSet)
                {
                    var anyMac = classified.FirstOrDefault(x => !string.IsNullOrEmpty(x.adapter["MACAddress"]?.ToString()));
                    scanStatus.MACAddress = anyMac.adapter != null
                        ? anyMac.adapter["MACAddress"]?.ToString() ?? "Not Available"
                        : "Not Available";
                }

                // ── Step 5: defaults for columns that got no adapter ─────────────────────
                if (!nic0Set) scanStatus.NIC0LAN  = "Not Present";
                if (!nic1Set) scanStatus.NIC1WiFi  = "Not Present";
                if (!nic2Set) scanStatus.NIC2LAN2  = "Not Present";
                if (!nic3Set) scanStatus.NIC3      = "Not Present";
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting network adapters info: {ex.Message}", context: "GetNetworkAdaptersInfoAsync");
                scanStatus.MACAddress = "Error";
                scanStatus.NIC0LAN    = "Error";
                scanStatus.NIC1WiFi   = "Error";
                scanStatus.NIC2LAN2   = "Error";
                scanStatus.NIC3       = "Error";
            }
        }

        // new method to add
        private async Task CheckPortsAsync(string ipAddress, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            try
            {
                var portMap = new Dictionary<int, string>
        {
            { 16992, nameof(ScanStatus.Port16992) },
            { 16993, nameof(ScanStatus.Port16993) },
            { 22, nameof(ScanStatus.Port22) },
            { 80, nameof(ScanStatus.Port80) },
            { 443, nameof(ScanStatus.Port443) },
            { 3389, nameof(ScanStatus.Port3389) },
            { 5985, nameof(ScanStatus.Port5985) }
        };

                var portTasks = new List<Task>();

                foreach (var portEntry in portMap)
                {
                    int port = portEntry.Key;
                    string propertyName = portEntry.Value;

                    if (dataColumnSettings.Any(c => c.IsSelected && c.Name == $"Port {port}"))
                    {
                        portTasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                var result = await IsPortOpenAsync(ipAddress, port, cancellationToken);
                                typeof(ScanStatus).GetProperty(propertyName).SetValue(
                                    scanStatus, result ? "Open" : "Closed");
                            }
                            catch (Exception ex)
                            {
                                typeof(ScanStatus).GetProperty(propertyName).SetValue(
                                    scanStatus, "Error");
                                Logger.Log(LogLevel.ERROR, $"Error checking port {port} on {ipAddress}: {ex.Message}",
                                    context: "CheckPortsAsync");
                            }
                        }, cancellationToken));
                    }
                }

                await Task.WhenAll(portTasks);
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error in port scanning for {ipAddress}: {ex.Message}",
                    context: "CheckPortsAsync");
            }
        }

        private async Task<bool> IsPortOpenAsync(string host, int port, CancellationToken cancellationToken)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(host, port);
                    var timeoutTask = Task.Delay(2000, cancellationToken); // 2 second timeout

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        return false; // Connection timed out
                    }

                    // Make sure the connection task completed without exception
                    await connectTask;

                    return client.Connected;
                }
            }
            catch
            {
                return false;
            }
        }

        private static readonly Dictionary<string, string> DefaultFloorMappings = new()
        {
            { "10.9.115", "30 Hudson 20 east" },
            { "10.9.116", "30 Hudson 20 west" },
            { "10.9.97",  "30 Hudson 25 west" },
            { "10.9.107", "30 Hudson 25 west" },
            { "10.9.96",  "30 Hudson 25 east" },
            { "10.9.99",  "30 Hudson 26 west" },
            { "10.9.109", "30 Hudson 26 west" },
            { "10.9.108", "30 Hudson 26 east" },
            { "10.9.101", "30 Hudson 27 west" },
            { "10.9.111", "30 Hudson 27 west" },
            { "10.9.114", "30 Hudson 27 west" },
            { "10.9.100", "30 Hudson 27 east" },
            { "10.9.110", "30 Hudson 27 east" },
            { "10.9.103", "30 Hudson 28 west" },
            { "10.9.102", "30 Hudson 28 east" },
            { "10.9.105", "30 Hudson 29 west" },
            { "10.9.104", "30 Hudson 29 east" },
            { "10.9.106", "30 Hudson 30 west" },
        };

        private void InitializeFloorMappings()
        {
            // Load from floor_mappings.json next to the exe, fall back to built-in defaults.
            string jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "floor_mappings.json");
            try
            {
                if (File.Exists(jsonPath))
                {
                    var json = File.ReadAllText(jsonPath);
                    floorMappings = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                                    ?? new Dictionary<string, string>(DefaultFloorMappings);
                    Logger.Log(LogLevel.INFO, $"Loaded floor mappings from {jsonPath}", context: "InitializeFloorMappings");
                    return;
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.WARNING, $"Could not load floor_mappings.json: {ex.Message}. Using defaults.", context: "InitializeFloorMappings");
            }
            floorMappings = new Dictionary<string, string>(DefaultFloorMappings);
        }

        private string GetFloorForIP(string ipAddress)
        {
            try
            {
                string[] parts = ipAddress.Split('.');
                if (parts.Length >= 3)
                {
                    string segment = $"{parts[0]}.{parts[1]}.{parts[2]}";
                    if (floorMappings.TryGetValue(segment, out string floor))
                    {
                        return floor;
                    }
                }
                return "Unknown";
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error determining floor for IP {ipAddress}: {ex.Message}", context: "GetFloorForIP");
                return "Error";
            }
        }

        private void UpdateScanStatus(ScanStatus scanStatus)
        {
            Dispatcher.Invoke(() =>
            {
                var existingStatus = ScanStatuses.FirstOrDefault(s => s.IPAddress == scanStatus.IPAddress);
                if (existingStatus != null)
                {
                    int index = ScanStatuses.IndexOf(existingStatus);
                    ScanStatuses[index] = scanStatus;
                }
                else
                {
                    ScanStatuses.Add(scanStatus);
                }
                UpdateResultCount();
            });
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            ScanStatuses.Clear();
            Logger.Log(LogLevel.INFO, "Grid data cleared by the user.");
            UpdateStatusBar("Grid cleared.");
        }


        // ── Search / Filter ─────────────────────────────────────────
        public void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (sender is TextBox tb)
            {
                _filterText = tb.Text.Trim();
                _scanView.Refresh();
                UpdateResultCount();
            }
        }

        private bool FilterRow(object item)
        {
            if (string.IsNullOrEmpty(_filterText)) return true;
            if (item is not ScanStatus s) return false;

            // Search across all string properties that have visible columns
            var visibleProps = dataColumnSettings
                .Where(c => c.IsSelected)
                .Select(c => c.PropertyName)
                .ToHashSet();

            return typeof(ScanStatus)
                .GetProperties()
                .Where(p => visibleProps.Contains(p.Name))
                .Select(p => p.GetValue(s)?.ToString() ?? "")
                .Any(v => v.Contains(_filterText, StringComparison.OrdinalIgnoreCase));
        }

        private void UpdateResultCount()
        {
            Dispatcher.Invoke(() =>
            {
                if (ResultCountText != null)
                {
                    int shown = _scanView.Cast<object>().Count();
                    int total = ScanStatuses.Count;
                    ResultCountText.Text = shown == total
                        ? $"{total} rows"
                        : $"{shown} of {total} rows";
                }
            });
        }

        private void UpdateStatusBar(string message)
        {
            Dispatcher.Invoke(() =>
            {
                StatusBarText.Text = message;
            });
        }

        private void UpdateProgressBar(int value, int done = 0, int total = 0)
        {
            Dispatcher.Invoke(() =>
            {
                ProgressBar.Value = value;
                if (ProgressText != null)
                {
                    ProgressText.Text = total > 0
                        ? $"{done} / {total}  ({value}%)"
                        : value > 0 ? $"{value}%" : "";
                }
            });
        }

        private void UpdateScanSummary()
        {
            Dispatcher.Invoke(() =>
            {
                int online   = ScanStatuses.Count(s => s.Status == "Complete" || s.Status == "Reachable");
                int offline  = ScanStatuses.Count(s => s.Status == "Not Reachable");
                int errors   = ScanStatuses.Count(s => s.Status is "Error" or "Fatal Error" or "Unexpected Error" or "Network Error");
                int timeout  = ScanStatuses.Count(s => s.Status == "Timeout");
                int total    = ScanStatuses.Count;
                UpdateStatusBar($"Done — {total} total | {online} online | {offline} offline | {errors} errors | {timeout} timeouts");
            });
        }

        private void DisableButtons()
        {
            Dispatcher.Invoke(() =>
            {
                if (ScanButton != null)
                {
                    ScanButton.IsEnabled = false;
                }
            });
        }

        private void EnableButtons()
        {
            Dispatcher.Invoke(() =>
            {
                if (ScanButton != null)
                {
                    ScanButton.IsEnabled = true;
                }
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

                var header = string.Join(",", dataColumnSettings.Where(c => c.IsSelected).Select(c => $"\"{c.Name}\""));

                if (fileExists)
                {
                    string existingHeader = File.ReadLines(outputFilePath).FirstOrDefault();

                    if (existingHeader != header)
                    {
                        var result = MessageBox.Show("The existing file has a different header. Do you want to overwrite it?", "Header Mismatch", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
                        if (result == MessageBoxResult.Cancel)
                        {
                            return;
                        }
                        else if (result == MessageBoxResult.Yes)
                        {
                            File.WriteAllText(outputFilePath, header + Environment.NewLine);
                        }
                        else if (result == MessageBoxResult.No)
                        {
                            File.AppendAllText(outputFilePath, header + Environment.NewLine);
                        }
                    }
                }
                else
                {
                    File.WriteAllText(outputFilePath, header + Environment.NewLine);
                }

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
                            var value = GetPropertyValue(scanStatus, c);
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

        private string GetPropertyValue(ScanStatus scanStatus, ColumnSetting column)
        {
            var property = typeof(ScanStatus).GetProperty(column.PropertyName);
            return property?.GetValue(scanStatus)?.ToString() ?? "N/A";
        }

        public class ScanStatus
        {
            public string IPAddress { get; set; }
            public string Hostname { get; set; }
            public string LastLoggedUser { get; set; }
            public string MachineModel { get; set; }
            public string RAMSize { get; set; }
            public string WindowsInfo { get; set; }
            public string MicrosoftOfficeVersion { get; set; }
            public string Date { get; set; }
            public string Time { get; set; }
            public string Status { get; set; }
            public string Details { get; set; }
            public string MACAddress { get; set; }
            public string DiskSize { get; set; }
            public string DiskFreeSpace { get; set; }
            public string OtherDrives { get; set; }
            public long PingTime { get; set; }
            public string BIOSVersionDate { get; set; }
            public string SMBIOSVersion { get; set; }
            public string EmbeddedControllerVersion { get; set; }
            public string NIC0LAN { get; set; }
            public string NIC1WiFi { get; set; }
            public string NIC2LAN2 { get; set; }
            public string NIC3 { get; set; }
            public string Port16992 { get; set; }
            public string Port16993 { get; set; }
            public string Port22 { get; set; }
            public string Port80 { get; set; }
            public string Port443 { get; set; }
            public string Port3389 { get; set; }
            public string Port5985 { get; set; }
            public string Floor { get; set; }

            public ScanStatus()
            {
                IPAddress = "";
                Hostname = "N/A";
                LastLoggedUser = "N/A";
                MachineModel = "N/A";
                RAMSize = "N/A";
                WindowsInfo = "N/A";
                MicrosoftOfficeVersion = "N/A";
                Date = DateTime.Now.ToString("M/dd/yyyy");
                Time = DateTime.Now.ToString("HH:mm");
                Status = "Not Started";
                Details = "N/A";
                MACAddress = "N/A";
                DiskSize = "N/A";
                DiskFreeSpace = "N/A";
                OtherDrives = "N/A";
                PingTime = -1;
                BIOSVersionDate = "N/A";
                SMBIOSVersion = "N/A";
                EmbeddedControllerVersion = "N/A";
                NIC0LAN = "N/A";
                NIC1WiFi = "N/A";
                NIC2LAN2 = "N/A";
                NIC3 = "N/A";
                Port16992 = "N/A";
                Port16993 = "N/A";
                Port22 = "N/A";
                Port80 = "N/A";
                Port443 = "N/A";
                Port3389 = "N/A";
                Port5985 = "N/A";
                Floor = "N/A";
            }
        }
    }
}