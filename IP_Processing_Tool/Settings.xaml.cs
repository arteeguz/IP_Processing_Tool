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
        public int ExecutionTimeLimit { get; set; }
        public bool DataRetrievalOptionsChanged { get; private set; }

        private ObservableCollection<ColumnSetting> originalDataColumns;

        public Settings(ObservableCollection<ColumnSetting> currentDataColumns, bool autoSave, int pingTimeout, int maxConcurrentScans, int executionTimeLimit)
        {
            InitializeComponent();
            originalDataColumns = new ObservableCollection<ColumnSetting>(currentDataColumns);
            DataColumns = new ObservableCollection<ColumnSetting>(currentDataColumns.Select(c => new ColumnSetting { Name = c.Name, IsSelected = c.IsSelected }));
            DataColumnsList.ItemsSource = DataColumns;
            AutoSave = autoSave;
            PingTimeout = pingTimeout;
            MaxConcurrentScans = maxConcurrentScans;
            ExecutionTimeLimit = executionTimeLimit;

            AutoSaveCheckBox.IsChecked = AutoSave;
            PingTimeoutTextBox.Text = PingTimeout.ToString();
            MaxConcurrentScansTextBox.Text = MaxConcurrentScans.ToString();
            ExecutionTimeLimitTextBox.Text = ExecutionTimeLimit.ToString();
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
            if (!int.TryParse(ExecutionTimeLimitTextBox.Text, out int executionTimeLimit) || executionTimeLimit <= 0)
            {
                MessageBox.Show("Please enter a valid positive integer for Execution Time Limit per IP.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
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