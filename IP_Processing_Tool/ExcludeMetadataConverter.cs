using System;
using System.Globalization;
using System.Windows.Data;

namespace IPProcessingTool
{
    public class ExcludeMetadataConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // List of metadata columns to exclude
            var metadataColumns = new[] { "IP Address", "Date", "Time", "Status", "Details" };
            return metadataColumns.Contains(value as string) ? System.Windows.Visibility.Collapsed : System.Windows.Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
