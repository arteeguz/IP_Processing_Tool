using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace IPProcessingTool
{
    public partial class Settings : Window
    {
        public ObservableCollection<ColumnSetting> DataColumns { get; set; }
        public ObservableCollection<FloorMappingEntry> FloorMappings { get; set; }
        public bool AutoSave { get; set; }
        public int PingTimeout { get; set; }
        public int MaxConcurrentScans { get; set; }
        public int ExecutionTimeLimit { get; set; }
        public bool DataRetrievalOptionsChanged { get; private set; }

        private ObservableCollection<ColumnSetting> originalDataColumns;

        public Settings(ObservableCollection<ColumnSetting> currentDataColumns, bool autoSave, int pingTimeout, int maxConcurrentScans, int executionTimeLimit, Dictionary<string, string> floorMappings)
        {
            InitializeComponent();

            // Initialize data
            originalDataColumns = new ObservableCollection<ColumnSetting>(
                currentDataColumns.Select(c => new ColumnSetting { Name = c.Name, PropertyName = c.PropertyName, IsSelected = c.IsSelected }));
            DataColumns = new ObservableCollection<ColumnSetting>(currentDataColumns.Select(c => new ColumnSetting { Name = c.Name, PropertyName = c.PropertyName, IsSelected = c.IsSelected }));
            DataColumnsList.ItemsSource = DataColumns;

            FloorMappings = new ObservableCollection<FloorMappingEntry>(
                (floorMappings ?? new Dictionary<string, string>())
                    .Select(kv => new FloorMappingEntry { Segment = kv.Key, Floor = kv.Value }));
            FloorMappingsGrid.ItemsSource = FloorMappings;

            AutoSave = autoSave;
            PingTimeout = pingTimeout == 0 ? 3000 : pingTimeout; // Use 3000ms if not set
            MaxConcurrentScans = maxConcurrentScans == 0 ? Environment.ProcessorCount : maxConcurrentScans; // Use processor count if not set
            ExecutionTimeLimit = executionTimeLimit == 0 ? 60 : executionTimeLimit; // Use 60 seconds if not set

            // Set UI values
            AutoSaveCheckBox.IsChecked = AutoSave;
            PingTimeoutTextBox.Text = PingTimeout.ToString();
            MaxConcurrentScansTextBox.Text = MaxConcurrentScans.ToString();
            ExecutionTimeLimitTextBox.Text = ExecutionTimeLimit.ToString();

            // Add input validation
            PingTimeoutTextBox.TextChanged += ValidateNumericInput;
            MaxConcurrentScansTextBox.TextChanged += ValidateNumericInput;
            ExecutionTimeLimitTextBox.TextChanged += ValidateNumericInput;
        }

        private void ValidateNumericInput(object sender, TextChangedEventArgs e)
        {
            if (sender is TextBox textBox)
            {
                // Reset border color
                textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(221, 221, 221)); // #DDD

                if (int.TryParse(textBox.Text, out int value))
                {
                    bool isValid = true;

                    // Validate based on which textbox
                    if (textBox == PingTimeoutTextBox)
                    {
                        isValid = value >= 1000 && value <= 10000;
                    }
                    else if (textBox == MaxConcurrentScansTextBox)
                    {
                        isValid = value >= 1 && value <= 50;
                    }
                    else if (textBox == ExecutionTimeLimitTextBox)
                    {
                        isValid = value >= 10 && value <= 300;
                    }

                    if (!isValid)
                    {
                        textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 53, 69)); // Red border for invalid
                    }
                    else
                    {
                        textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(40, 167, 69)); // Green border for valid
                    }
                }
                else if (!string.IsNullOrEmpty(textBox.Text))
                {
                    textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 53, 69)); // Red border for invalid
                }
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            if (ValidateSettings())
            {
                AutoSave = AutoSaveCheckBox.IsChecked ?? false;
                PingTimeout = int.Parse(PingTimeoutTextBox.Text);
                MaxConcurrentScans = int.Parse(MaxConcurrentScansTextBox.Text);
                ExecutionTimeLimit = int.Parse(ExecutionTimeLimitTextBox.Text);

                // Check if data retrieval options have changed
                DataRetrievalOptionsChanged = HasDataRetrievalOptionsChanged();

                // Save floor mappings to JSON
                var mappingsDict = FloorMappings
                    .Where(e => !string.IsNullOrWhiteSpace(e.Segment))
                    .ToDictionary(e => e.Segment.Trim(), e => e.Floor.Trim());
                string jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "floor_mappings.json");
                File.WriteAllText(jsonPath, JsonSerializer.Serialize(mappingsDict, new JsonSerializerOptions { WriteIndented = true }));

                DialogResult = true;
                Close();
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private bool ValidateSettings()
        {
            var errors = new List<string>();

            // Validate Ping Timeout
            if (!int.TryParse(PingTimeoutTextBox.Text, out int pingTimeout) || pingTimeout < 1000 || pingTimeout > 10000)
            {
                errors.Add("• Ping Timeout must be between 1000 and 10000 milliseconds");
                PingTimeoutTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 53, 69));
            }

            // Validate Max Concurrent Scans
            if (!int.TryParse(MaxConcurrentScansTextBox.Text, out int maxConcurrentScans) || maxConcurrentScans < 1 || maxConcurrentScans > 50)
            {
                errors.Add("• Max Concurrent Scans must be between 1 and 50");
                MaxConcurrentScansTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 53, 69));
            }

            // Validate Execution Time Limit
            if (!int.TryParse(ExecutionTimeLimitTextBox.Text, out int executionTimeLimit) || executionTimeLimit < 10 || executionTimeLimit > 300)
            {
                errors.Add("• Execution Time Limit must be between 10 and 300 seconds");
                ExecutionTimeLimitTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 53, 69));
            }

            if (errors.Any())
            {
                string errorMessage = "Please correct the following issues:\n\n" + string.Join("\n", errors);

                // Create a custom message box that matches our theme
                var result = MessageBox.Show(errorMessage, "⚠️ Invalid Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            return true;
        }

        private bool HasDataRetrievalOptionsChanged()
        {
            return !DataColumns.SequenceEqual(originalDataColumns, new ColumnSettingComparer());
        }

        private void AddMappingRow_Click(object sender, RoutedEventArgs e)
        {
            FloorMappings.Add(new FloorMappingEntry());
            FloorMappingsGrid.ScrollIntoView(FloorMappings[FloorMappings.Count - 1]);
        }

        private void RemoveMappingRow_Click(object sender, RoutedEventArgs e)
        {
            if (FloorMappingsGrid.SelectedItem is FloorMappingEntry selected)
                FloorMappings.Remove(selected);
        }

    }

    public class FloorMappingEntry
    {
        public string Segment { get; set; } = "";
        public string Floor   { get; set; } = "";
    }

    public class ColumnSetting
    {
        public string Name { get; set; }
        /// <summary>
        /// The exact property name on ScanStatus that this column binds to.
        /// Avoids fragile Name.Replace(" ", "") string manipulation.
        /// </summary>
        public string PropertyName { get; set; }
        public bool IsSelected { get; set; }
    }

    public class ColumnSettingComparer : IEqualityComparer<ColumnSetting>
    {
        public bool Equals(ColumnSetting x, ColumnSetting y)
        {
            return x.Name == y.Name && x.IsSelected == y.IsSelected;
        }

        public int GetHashCode(ColumnSetting obj)
        {
            return obj.Name.GetHashCode() ^ obj.IsSelected.GetHashCode();
        }
    }
}