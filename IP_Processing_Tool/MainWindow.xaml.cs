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
        private const int BATCH_SIZE = 50;
        private List<ScanStatus> _batch = new List<ScanStatus>();

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

            InitializeFloorMappings();
            InitializeColumnSettings();
            UpdateDataGridColumns();

            Logger.Log(LogLevel.INFO, "Application started");
        }

        // previous code
        private void InitializeColumnSettings()
        {
            dataColumnSettings = new ObservableCollection<ColumnSetting>
            {
                new ColumnSetting { Name = "IP Address", IsSelected = true },
                new ColumnSetting { Name = "Hostname", IsSelected = true },
                new ColumnSetting { Name = "Last Logged User", IsSelected = true },
                new ColumnSetting { Name = "Machine Model", IsSelected = true },
                new ColumnSetting { Name = "Disk Size", IsSelected = true },
                new ColumnSetting { Name = "Disk Free Space", IsSelected = true },
                new ColumnSetting { Name = "Other Drives", IsSelected = true },
                new ColumnSetting { Name = "RAM Size", IsSelected = true },
                new ColumnSetting { Name = "Windows Info", IsSelected = true },
                new ColumnSetting { Name = "Microsoft Office Version", IsSelected = true },
                new ColumnSetting { Name = "BIOS Version Date", IsSelected = true },
                new ColumnSetting { Name = "SMBIOS Version", IsSelected = true },
                new ColumnSetting { Name = "Embedded Controller Version", IsSelected = true },
                new ColumnSetting { Name = "MAC Address", IsSelected = true },
                new ColumnSetting { Name = "NIC 0 LAN", IsSelected = true },
                new ColumnSetting { Name = "NIC 1 WiFi", IsSelected = true },
                new ColumnSetting { Name = "NIC 2 LAN 2", IsSelected = true },
                new ColumnSetting { Name = "Date", IsSelected = true },
                new ColumnSetting { Name = "Time", IsSelected = true },
                new ColumnSetting { Name = "Ping Time", IsSelected = true },
                new ColumnSetting { Name = "Status", IsSelected = true },
                new ColumnSetting { Name = "Details", IsSelected = true },
                new ColumnSetting { Name = "Port 16992", IsSelected = true },
                new ColumnSetting { Name = "Port 16993", IsSelected = true },
                new ColumnSetting { Name = "Port 22", IsSelected = false },
                new ColumnSetting { Name = "Port 80", IsSelected = false },
                new ColumnSetting { Name = "Port 443", IsSelected = false },
                new ColumnSetting { Name = "Port 3389", IsSelected = false },
                new ColumnSetting { Name = "Port 5985", IsSelected = false },
                new ColumnSetting { Name = "Floor", IsSelected = true },
            };
        }

        private void UpdateDataGridColumns()
        {
            StatusDataGrid.Columns.Clear();
            foreach (var column in dataColumnSettings.Where(c => c.IsSelected))
            {
                if (column.Name == "Ping Time")
                {
                    StatusDataGrid.Columns.Add(new DataGridTextColumn
                    {
                        Header = column.Name,
                        Binding = new System.Windows.Data.Binding("PingTime") { StringFormat = "{0} ms" }
                    });
                }
                else
                {
                    StatusDataGrid.Columns.Add(new DataGridTextColumn
                    {
                        Header = column.Name,
                        Binding = new System.Windows.Data.Binding(column.Name.Replace(" ", ""))
                    });
                }
            }
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

        private async Task ProcessIPsAsync(IEnumerable<string> ipsOrHostnames)
        {
            var resolvedIPs = new List<(string original, string resolved)>();

            // First, resolve all hostnames to IPs
            UpdateStatusBar("Resolving hostnames...");
            foreach (var entry in ipsOrHostnames)
            {
                var resolvedIP = await ResolveHostnameToIPAsync(entry);
                if (!string.IsNullOrEmpty(resolvedIP))
                {
                    resolvedIPs.Add((entry, resolvedIP));
                }
                else
                {
                    // Add failed resolution to the grid immediately
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
            UpdateProgressBar(0);

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
                            Interlocked.Increment(ref processedIPs);
                            UpdateProgressBar((int)((double)processedIPs / totalIPs * 100));
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
                UpdateStatusBar("Completed processing all IPs.");
                UpdateProgressBar(100);

                Dispatcher.Invoke(() =>
                {
                    StatusDataGrid.Items.Refresh();
                });

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

        private async void Button1_Click(object sender, RoutedEventArgs e)
        {
            var inputWindow = new InputWindow("Enter IP address or hostname:", false);
            if (inputWindow.ShowDialog() == true)
            {
                string[] entries = inputWindow.InputText.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                Logger.Log(LogLevel.INFO, "User input IP addresses/hostnames", context: "Button1_Click", additionalInfo: string.Join(", ", entries));
                await ProcessIPsAsync(entries);
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
                    }
                    else
                    {
                        MessageBox.Show($"An error occurred while accessing the file: {ex.Message}", "File Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private async void Button3_Click(object sender, RoutedEventArgs e)
        {
            var inputWindow = new InputWindow("Enter the IP segment:", true);
            if (inputWindow.ShowDialog() == true)
            {
                string[] segments = inputWindow.InputText.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                Logger.Log(LogLevel.INFO, "User input IP segments", context: "Button3_Click", additionalInfo: string.Join(", ", segments));
                var ips = segments.SelectMany(segment => Enumerable.Range(0, 256).Select(i => $"{segment}.{i}"));
                await ProcessIPsAsync(ips);
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
                        MessageBox.Show($"An error occurred while accessing the file: {ex.Message}", "File Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
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

                            if (dataColumnSettings.Any(c => c.IsSelected && (c.Name == "NIC 0 LAN" || c.Name == "NIC 1 WiFi" || c.Name == "NIC 2 LAN 2" || c.Name == "MAC Address")))
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
            try
            {
                var modelQuery = new ObjectQuery("SELECT Version FROM Win32_ComputerSystemProduct");
                using var modelSearcher = new ManagementObjectSearcher(scope, modelQuery);
                var model = await Task.Run(() => modelSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);
                if (model != null)
                {
                    scanStatus.MachineModel = model["Version"]?.ToString() ?? "N/A";
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
                // Query for BIOS information
                var biosQuery = new ObjectQuery("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
                using var biosSearcher = new ManagementObjectSearcher(scope, biosQuery);
                var bios = await Task.Run(() => biosSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);

                if (bios != null)
                {
                    string manufacturer = bios["Manufacturer"]?.ToString() ?? "Unknown";
                    string smbiosBiosVersion = bios["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown";
                    string releaseDate = bios["ReleaseDate"]?.ToString() ?? "Unknown";

                    // Attempt to parse the release date
                    if (releaseDate != "Unknown" && DateTime.TryParseExact(releaseDate.Split('.')[0], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime parsedDate))
                    {
                        releaseDate = parsedDate.ToString("M/d/yyyy");
                    }

                    scanStatus.BIOSVersionDate = $"{manufacturer}, {smbiosBiosVersion}, {releaseDate}";
                }
                else
                {
                    scanStatus.BIOSVersionDate = "BIOS information not available";
                }

                // Query for SMBIOS Version
                var smbiosQuery = new ObjectQuery("SELECT SMBIOSMajorVersion, SMBIOSMinorVersion FROM Win32_BIOS");
                using var smbiosSearcher = new ManagementObjectSearcher(scope, smbiosQuery);
                var smbios = await Task.Run(() => smbiosSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);

                if (smbios != null)
                {
                    int smbiosMajorVersion = Convert.ToInt32(smbios["SMBIOSMajorVersion"]);
                    int smbiosMinorVersion = Convert.ToInt32(smbios["SMBIOSMinorVersion"]);
                    scanStatus.SMBIOSVersion = $"{smbiosMajorVersion}.{smbiosMinorVersion}";
                }
                else
                {
                    scanStatus.SMBIOSVersion = "SMBIOS information not available";
                }

                // Query for Embedded Controller Version
                var ecQuery = new ObjectQuery("SELECT EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion FROM Win32_BIOS");
                using var ecSearcher = new ManagementObjectSearcher(scope, ecQuery);
                var ecInfo = await Task.Run(() => ecSearcher.Get().Cast<ManagementObject>().FirstOrDefault(), cancellationToken);

                if (ecInfo != null)
                {
                    int ecMajorVersion = Convert.ToInt32(ecInfo["EmbeddedControllerMajorVersion"]);
                    int ecMinorVersion = Convert.ToInt32(ecInfo["EmbeddedControllerMinorVersion"]);
                    scanStatus.EmbeddedControllerVersion = $"{ecMajorVersion}.{ecMinorVersion}";
                }
                else
                {
                    scanStatus.EmbeddedControllerVersion = "Embedded Controller information not available";
                }
            }
            catch (Exception ex)
            {
                scanStatus.BIOSVersionDate = "Error retrieving BIOS information";
                scanStatus.SMBIOSVersion = "Error";
                scanStatus.EmbeddedControllerVersion = "Error";
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
            try
            {
                var query = new ObjectQuery(@"SELECT * FROM Win32_Registry");
                using var searcher = new ManagementObjectSearcher(scope, query);
                var registryEntries = await Task.Run(() => searcher.Get(), cancellationToken);

                foreach (ManagementObject registryEntry in registryEntries)
                {
                    using var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, scope.Path.Server);
                    using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

                    if (key != null)
                    {
                        string displayVersion = key.GetValue("DisplayVersion") as string;
                        if (!string.IsNullOrEmpty(displayVersion))
                        {
                            return displayVersion;
                        }

                        // Fallback for older versions
                        string releaseId = key.GetValue("ReleaseId") as string;
                        if (!string.IsNullOrEmpty(releaseId))
                        {
                            return releaseId;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting Windows release ID: {ex.Message}", context: "GetWindowsReleaseIdAsync");
            }
            return "Unknown";
        }

        private async Task GetOfficeVersionAsync(string machineName, ScanStatus scanStatus, CancellationToken cancellationToken)
        {
            string officeVersion = "Not Installed";
            string registryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            string[] officeKeywords = new[] { "Microsoft Office", "Office 365", "Microsoft 365" };

            try
            {
                await Task.Run(() =>
                {
                    try
                    {
                        using (RegistryKey baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machineName))
                        using (RegistryKey uninstallKey = baseKey.OpenSubKey(registryPath))
                        {
                            if (uninstallKey != null)
                            {
                                foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                                {
                                    cancellationToken.ThrowIfCancellationRequested();

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
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex) when (!(ex is OperationCanceledException))
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
                var query = new ObjectQuery("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True");
                using var searcher = new ManagementObjectSearcher(scope, query);
                var adapters = await Task.Run(() => searcher.Get(), cancellationToken);

                bool macAddressSet = false;
                bool nic0Set = false;
                bool nic1Set = false;
                bool nic2Set = false;

                foreach (ManagementObject adapter in adapters)
                {
                    string adapterType = adapter["AdapterType"]?.ToString() ?? "";
                    string name = adapter["Name"]?.ToString() ?? "Unknown";
                    string macAddress = adapter["MACAddress"]?.ToString();
                    bool netEnabled = Convert.ToBoolean(adapter["NetEnabled"]);
                    string speed = adapter["Speed"] != null ? $"{Convert.ToInt64(adapter["Speed"]) / 1000000} Mbps" : "N/A";

                    // Always set the MAC Address if it's not set yet, regardless of adapter type or NetEnabled status
                    if (!macAddressSet && !string.IsNullOrEmpty(macAddress))
                    {
                        scanStatus.MACAddress = macAddress;
                        macAddressSet = true;
                    }

                    // Only set NIC info if the adapter is enabled and we're scanning for it
                    if (netEnabled)
                    {
                        if (adapterType.Contains("Ethernet", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!nic0Set && dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 0 LAN"))
                            {
                                scanStatus.NIC0LAN = $"{name} | MAC: {macAddress} | Speed: {speed}";
                                nic0Set = true;
                            }
                            else if (!nic2Set && dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 2 LAN 2"))
                            {
                                scanStatus.NIC2LAN2 = $"{name} | MAC: {macAddress} | Speed: {speed}";
                                nic2Set = true;
                            }
                        }
                        else if ((adapterType.Contains("Wireless", StringComparison.OrdinalIgnoreCase) ||
                                  name.Contains("WiFi", StringComparison.OrdinalIgnoreCase) ||
                                  name.Contains("Wireless", StringComparison.OrdinalIgnoreCase)) &&
                                 !nic1Set && dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 1 WiFi"))
                        {
                            scanStatus.NIC1WiFi = $"{name} | MAC: {macAddress} | Speed: {speed}";
                            nic1Set = true;
                        }
                    }

                    // Break if we've set everything we need
                    if (macAddressSet && nic0Set && nic1Set && nic2Set) break;
                }

                // Set default values for unset properties
                if (!macAddressSet) scanStatus.MACAddress = "Not Available";
                if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 0 LAN") && !nic0Set) scanStatus.NIC0LAN = "Not Present";
                if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 1 WiFi") && !nic1Set) scanStatus.NIC1WiFi = "Not Present";
                if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 2 LAN 2") && !nic2Set) scanStatus.NIC2LAN2 = "Not Present";
            }
            catch (Exception ex)
            {
                Logger.Log(LogLevel.ERROR, $"Error getting network adapters info: {ex.Message}", context: "GetNetworkAdaptersInfoAsync");
                scanStatus.MACAddress = "Error";
                if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 0 LAN")) scanStatus.NIC0LAN = "Error retrieving data";
                if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 1 WiFi")) scanStatus.NIC1WiFi = "Error retrieving data";
                if (dataColumnSettings.Any(c => c.IsSelected && c.Name == "NIC 2 LAN 2")) scanStatus.NIC2LAN2 = "Error retrieving data";
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

        private void InitializeFloorMappings()
        {
            floorMappings = new Dictionary<string, string>
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
                StatusDataGrid.Items.Refresh();
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
            UpdateScanStatus(scanStatus);
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