using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace IPProcessingTool
{
    public class AppSettings
    {
        public int PingTimeout { get; set; } = 1000;
        public int MaxConcurrentScans { get; set; } = Environment.ProcessorCount;
        public int ExecutionTimeLimit { get; set; } = 60;
        public bool AutoSave { get; set; } = false;
        public List<ColumnSettingData> Columns { get; set; } = new();

        private static readonly string SettingsDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "IPProcessingTool");
        private static readonly string SettingsPath = Path.Combine(SettingsDir, "settings.json");

        public static AppSettings Load()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch { /* fall through to defaults */ }
            return new AppSettings();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(SettingsDir);
                var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(SettingsPath, json);
            }
            catch { /* non-fatal */ }
        }
    }

    /// <summary>Serializable snapshot of a ColumnSetting (no UI dependencies).</summary>
    public class ColumnSettingData
    {
        public string Name { get; set; }
        public string PropertyName { get; set; }
        public bool IsSelected { get; set; }
    }
}
