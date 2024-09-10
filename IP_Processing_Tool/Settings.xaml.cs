using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;

namespace IPProcessingTool
{
    public partial class Settings : Window
    {
        public ObservableCollection<ColumnSetting> DataColumns { get; set; }
        public bool AutoSave { get; set; }
        public int PingTimeout { get; set; }
        public int MaxConcurrentScans { get; set; }
        public int IndividualScanTimeout { get; set; }
        public int WmiOperationTimeout { get; set; }
        public double ScanCompletionThreshold { get; set; }
        public int FinalWaitTime { get; set; }
        public bool DataRetrievalOptionsChanged { get; private set; }

        private ObservableCollection<ColumnSetting> originalDataColumns;

        public Settings(ObservableCollection<ColumnSetting> currentDataColumns, bool autoSave, int pingTimeout, int maxConcurrentScans,
                        int individualScanTimeout, int wmiOperationTimeout, double scanCompletionThreshold, int finalWaitTime)
        {
            InitializeComponent();
            originalDataColumns = new ObservableCollection<ColumnSetting>(currentDataColumns);
            DataColumns = new ObservableCollection<ColumnSetting>(currentDataColumns.Select(c => new ColumnSetting { Name = c.Name, IsSelected = c.IsSelected }));
            DataColumnsList.ItemsSource = DataColumns;
            AutoSave = autoSave;
            PingTimeout = pingTimeout;
            MaxConcurrentScans = maxConcurrentScans;
            IndividualScanTimeout = individualScanTimeout;
            WmiOperationTimeout = wmiOperationTimeout;
            ScanCompletionThreshold = scanCompletionThreshold;
            FinalWaitTime = finalWaitTime;

            AutoSaveCheckBox.IsChecked = AutoSave;
            PingTimeoutTextBox.Text = PingTimeout.ToString();
            MaxConcurrentScansTextBox.Text = MaxConcurrentScans.ToString();
            IndividualScanTimeoutTextBox.Text = IndividualScanTimeout.ToString();
            WmiOperationTimeoutTextBox.Text = WmiOperationTimeout.ToString();
            ScanCompletionThresholdTextBox.Text = ScanCompletionThreshold.ToString();
            FinalWaitTimeTextBox.Text = FinalWaitTime.ToString();
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            if (ValidateSettings())
            {
                AutoSave = AutoSaveCheckBox.IsChecked ?? false;
                PingTimeout = int.Parse(PingTimeoutTextBox.Text);
                MaxConcurrentScans = int.Parse(MaxConcurrentScansTextBox.Text);
                IndividualScanTimeout = int.Parse(IndividualScanTimeoutTextBox.Text);
                WmiOperationTimeout = int.Parse(WmiOperationTimeoutTextBox.Text);
                ScanCompletionThreshold = double.Parse(ScanCompletionThresholdTextBox.Text);
                FinalWaitTime = int.Parse(FinalWaitTimeTextBox.Text);

                // Check if data retrieval options have changed
                DataRetrievalOptionsChanged = HasDataRetrievalOptionsChanged();

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
            if (!int.TryParse(PingTimeoutTextBox.Text, out int pingTimeout) || pingTimeout <= 0)
            {
                MessageBox.Show("Please enter a valid positive integer for Ping Timeout.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (!int.TryParse(MaxConcurrentScansTextBox.Text, out int maxConcurrentScans) || maxConcurrentScans <= 0)
            {
                MessageBox.Show("Please enter a valid positive integer for Max Concurrent Scans.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (!int.TryParse(IndividualScanTimeoutTextBox.Text, out int individualScanTimeout) || individualScanTimeout <= 0)
            {
                MessageBox.Show("Please enter a valid positive integer for Individual Scan Timeout.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (!int.TryParse(WmiOperationTimeoutTextBox.Text, out int wmiOperationTimeout) || wmiOperationTimeout <= 0)
            {
                MessageBox.Show("Please enter a valid positive integer for WMI Operation Timeout.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (!double.TryParse(ScanCompletionThresholdTextBox.Text, out double scanCompletionThreshold) || scanCompletionThreshold <= 0 || scanCompletionThreshold > 1)
            {
                MessageBox.Show("Please enter a valid number between 0 and 1 for Scan Completion Threshold.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (!int.TryParse(FinalWaitTimeTextBox.Text, out int finalWaitTime) || finalWaitTime <= 0)
            {
                MessageBox.Show("Please enter a valid positive integer for Final Wait Time.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            return true;
        }

        private bool HasDataRetrievalOptionsChanged()
        {
            return !DataColumns.SequenceEqual(originalDataColumns, new ColumnSettingComparer());
        }
    }

    public class ColumnSetting
    {
        public string Name { get; set; }
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