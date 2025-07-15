using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace IPProcessingTool
{
    public partial class ModernInputWindow : Window
    {
        private const string PLACEHOLDER_TEXT = "Enter one or more targets (one per line):\n• IP addresses: 192.168.1.1\n• Hostnames: google.com, server01.company.com\n• IP ranges: 192.168.1.1-192.168.1.100\n• CIDR notation: 192.168.1.0/24\n• Segments: 192.168.1 (expands to .0-.255)";

        public List<string> ProcessedTargets { get; private set; }
        private string selectedFilePath;
        private HashSet<string> previewItems = new HashSet<string>();

        public ModernInputWindow()
        {
            InitializeComponent();
            ProcessedTargets = new List<string>();

            // Delay UpdateUI call until after XAML is loaded
            Loaded += (s, e) => UpdateUI();
        }

        private void InputTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            if (InputTextBox?.Text == PLACEHOLDER_TEXT)
            {
                InputTextBox.Text = "";
                InputTextBox.Foreground = new SolidColorBrush(Color.FromRgb(51, 51, 51));
            }
        }

        private void InputTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(InputTextBox?.Text))
            {
                if (InputTextBox != null)
                {
                    InputTextBox.Text = PLACEHOLDER_TEXT;
                    InputTextBox.Foreground = new SolidColorBrush(Color.FromRgb(153, 153, 153));
                }
            }
        }

        private void InputTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            UpdateUI();
        }

        private void PasteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    string clipboardText = Clipboard.GetText();
                    if (!string.IsNullOrWhiteSpace(clipboardText) && InputTextBox != null)
                    {
                        if (InputTextBox.Text == PLACEHOLDER_TEXT)
                        {
                            InputTextBox.Text = clipboardText;
                            InputTextBox.Foreground = new SolidColorBrush(Color.FromRgb(51, 51, 51));
                        }
                        else
                        {
                            InputTextBox.Text += Environment.NewLine + clipboardText;
                        }
                        ShowStatus("✅ Success", "Content pasted from clipboard", "#4CAF50");
                    }
                }
                else
                {
                    ShowStatus("⚠️ Warning", "No text content found in clipboard", "#FF9800");
                }
            }
            catch (Exception ex)
            {
                ShowStatus("❌ Error", $"Error accessing clipboard: {ex.Message}", "#F44336");
            }
        }

        private void ClearInput_Click(object sender, RoutedEventArgs e)
        {
            if (InputTextBox != null)
            {
                InputTextBox.Text = PLACEHOLDER_TEXT;
                InputTextBox.Foreground = new SolidColorBrush(Color.FromRgb(153, 153, 153));
            }
            UpdateUI();
        }

        private void SelectFileButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "Select Input File"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                selectedFilePath = openFileDialog.FileName;
                if (SelectedFileLabel != null)
                {
                    SelectedFileLabel.Text = Path.GetFileName(selectedFilePath);
                    SelectedFileLabel.Foreground = new SolidColorBrush(Color.FromRgb(40, 167, 69));
                    SelectedFileLabel.FontStyle = FontStyles.Normal;
                }
                UpdateUI();
            }
        }

        private void ProcessInput_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var newTargets = new HashSet<string>();

                // Process manual input
                if (InputTextBox?.Text != PLACEHOLDER_TEXT && !string.IsNullOrWhiteSpace(InputTextBox?.Text))
                {
                    var manualTargets = ParseInput(InputTextBox.Text);
                    foreach (var target in manualTargets)
                    {
                        newTargets.Add(target);
                    }
                }

                // Process file input
                if (!string.IsNullOrEmpty(selectedFilePath))
                {
                    var fileTargets = ProcessFile(selectedFilePath);
                    foreach (var target in fileTargets)
                    {
                        newTargets.Add(target);
                    }
                }

                // Add to preview (background processing)
                int previousCount = previewItems.Count;
                foreach (var target in newTargets)
                {
                    previewItems.Add(target);
                }

                UpdateUI();

                int addedCount = previewItems.Count - previousCount;
                if (addedCount > 0)
                {
                    ShowStatus("✅ Success", $"Added {addedCount} new targets. Total: {previewItems.Count} targets ready to scan", "#4CAF50");
                }
                else if (newTargets.Count > 0)
                {
                    ShowStatus("ℹ️ Info", "All targets were already in the list", "#2196F3");
                }
                else
                {
                    ShowStatus("⚠️ Warning", "No valid targets found to add", "#FF9800");
                }
            }
            catch (Exception ex)
            {
                ShowStatus("❌ Error", $"Error processing input: {ex.Message}", "#F44336");
            }
        }

        private void ClearPreview_Click(object sender, RoutedEventArgs e)
        {
            previewItems.Clear();
            UpdateUI();
            ShowStatus("ℹ️ Info", "All targets cleared", "#2196F3");
        }

        private void StartScan_Click(object sender, RoutedEventArgs e)
        {
            ProcessedTargets = previewItems.ToList();
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private List<string> ParseInput(string input)
        {
            var targets = new List<string>();
            var lines = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#") || trimmedLine.StartsWith("//"))
                    continue;

                var parsedTargets = ParseSingleLine(trimmedLine);
                targets.AddRange(parsedTargets);
            }

            return targets;
        }

        private List<string> ParseSingleLine(string input)
        {
            var targets = new List<string>();

            // Remove any comments at the end of the line
            int commentIndex = input.IndexOf("#");
            if (commentIndex >= 0)
                input = input.Substring(0, commentIndex).Trim();

            // Split by common delimiters
            var delimiters = new[] { ",", ";", "\t", " " };
            var parts = input.Split(delimiters, StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmedPart = part.Trim();
                if (string.IsNullOrEmpty(trimmedPart))
                    continue;

                targets.AddRange(ParseSingleTarget(trimmedPart));
            }

            return targets;
        }

        private List<string> ParseSingleTarget(string target)
        {
            // CIDR notation (e.g., 192.168.1.0/24)
            if (target.Contains("/"))
            {
                return ExpandCIDR(target);
            }

            // IP range (e.g., 192.168.1.1-192.168.1.100)
            if (target.Contains("-") && IsIPRange(target))
            {
                return ExpandIPRange(target);
            }

            // IP segment (e.g., 192.168.1)
            if (IsIPSegment(target))
            {
                return ExpandIPSegment(target);
            }

            // Single IP or hostname
            if (IsValidIPOrHostname(target))
            {
                return new List<string> { target };
            }

            return new List<string>();
        }

        private List<string> ExpandCIDR(string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var baseIP) || !int.TryParse(parts[1], out var prefixLength))
                    return new List<string>();

                if (prefixLength < 0 || prefixLength > 32)
                    return new List<string>();

                var results = new List<string>();
                uint mask = (uint)(0xFFFFFFFF << (32 - prefixLength));
                uint baseAddr = BitConverter.ToUInt32(baseIP.GetAddressBytes().Reverse().ToArray(), 0);
                uint networkAddr = baseAddr & mask;
                uint broadcastAddr = networkAddr | ~mask;

                for (uint addr = networkAddr; addr <= broadcastAddr; addr++)
                {
                    var bytes = BitConverter.GetBytes(addr).Reverse().ToArray();
                    var ip = new IPAddress(bytes);
                    results.Add(ip.ToString());
                }

                return results;
            }
            catch
            {
                return new List<string>();
            }
        }

        private List<string> ExpandIPRange(string range)
        {
            try
            {
                var parts = range.Split('-');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0].Trim(), out var startIP) || !IPAddress.TryParse(parts[1].Trim(), out var endIP))
                    return new List<string>();

                var results = new List<string>();
                uint start = BitConverter.ToUInt32(startIP.GetAddressBytes().Reverse().ToArray(), 0);
                uint end = BitConverter.ToUInt32(endIP.GetAddressBytes().Reverse().ToArray(), 0);

                if (start > end)
                {
                    (start, end) = (end, start);
                }

                for (uint addr = start; addr <= end; addr++)
                {
                    var bytes = BitConverter.GetBytes(addr).Reverse().ToArray();
                    var ip = new IPAddress(bytes);
                    results.Add(ip.ToString());
                }

                return results;
            }
            catch
            {
                return new List<string>();
            }
        }

        private List<string> ExpandIPSegment(string segment)
        {
            var results = new List<string>();
            for (int i = 0; i <= 255; i++)
            {
                results.Add($"{segment}.{i}");
            }
            return results;
        }

        private bool IsIPRange(string input)
        {
            var parts = input.Split('-');
            if (parts.Length != 2)
                return false;

            return IPAddress.TryParse(parts[0].Trim(), out _) && IPAddress.TryParse(parts[1].Trim(), out _);
        }

        private bool IsIPSegment(string input)
        {
            var parts = input.Split('.');
            if (parts.Length != 3)
                return false;

            return parts.All(part => byte.TryParse(part, out _));
        }

        private bool IsValidIPOrHostname(string input)
        {
            // Check if it's a valid IP
            if (IPAddress.TryParse(input, out _))
                return true;

            // Check if it's a valid hostname
            if (string.IsNullOrWhiteSpace(input) || input.Length > 253)
                return false;

            string hostnamePattern = @"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$";
            return Regex.IsMatch(input, hostnamePattern);
        }

        private List<string> ProcessFile(string filePath)
        {
            try
            {
                var content = File.ReadAllText(filePath);
                return ParseInput(content);
            }
            catch (Exception ex)
            {
                ShowStatus("❌ Error", $"Error reading file: {ex.Message}", "#F44336");
                return new List<string>();
            }
        }

        private void UpdateUI()
        {
            // Update count label in the header
            if (FindName("CountLabel") is TextBlock countLabel)
            {
                countLabel.Text = previewItems.Count > 0 ? $"({previewItems.Count} targets)" : "";
            }

            // Update estimate label with null check
            if (EstimateLabel != null)
            {
                EstimateLabel.Text = previewItems.Count > 0 ?
                    $"Estimated scan time: ~{CalculateEstimatedTime(previewItems.Count)}" : "";
            }

            // Enable/disable start scan button with null check
            if (StartScanButton != null)
            {
                StartScanButton.IsEnabled = previewItems.Count > 0;
            }

            // Update process button state with null check
            bool hasInput = (InputTextBox?.Text != PLACEHOLDER_TEXT && !string.IsNullOrWhiteSpace(InputTextBox?.Text))
                           || !string.IsNullOrEmpty(selectedFilePath);
            if (ProcessInputButton != null)
            {
                ProcessInputButton.IsEnabled = hasInput;
            }
        }

        private string CalculateEstimatedTime(int targetCount)
        {
            // Rough estimate: ~2-5 seconds per IP depending on network conditions
            int estimatedSeconds = targetCount * 3;

            if (estimatedSeconds < 60)
                return $"{estimatedSeconds}s";
            else if (estimatedSeconds < 3600)
                return $"{estimatedSeconds / 60}m {estimatedSeconds % 60}s";
            else
                return $"{estimatedSeconds / 3600}h {(estimatedSeconds % 3600) / 60}m";
        }

        private void ShowStatus(string title, string message, string colorHex)
        {
            if (StatusTitle != null && StatusMessage != null && StatusBorder != null)
            {
                StatusTitle.Text = title;
                StatusMessage.Text = message;
                StatusBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex + "33")); // 20% opacity
                StatusBorder.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex));
                StatusBorder.Visibility = Visibility.Visible;

                // Auto-hide after 5 seconds
                var timer = new System.Windows.Threading.DispatcherTimer();
                timer.Interval = TimeSpan.FromSeconds(5);
                timer.Tick += (s, e) => {
                    if (StatusBorder != null)
                    {
                        StatusBorder.Visibility = Visibility.Collapsed;
                    }
                    timer.Stop();
                };
                timer.Start();
            }
        }
    }
}