using System;
using System.IO;
using System.Security.Principal;

namespace IPProcessingTool
{
    public static class Logger
    {
        // Log file sits next to the EXE — shared location for all runs (audit trail)
        private static readonly string logFilePath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "app.log");

        // Set at app startup: the Windows user physically logged into this machine
        // (read from LogonUI registry key — different from the RunAs/admin account)
        public static string InteractiveUser { get; set; } = "";

        public static void Log(LogLevel level, string message, string context = "", string additionalInfo = "")
        {
            string processUser = GetCurrentUsername();
            string logonUser = string.IsNullOrEmpty(InteractiveUser) ? processUser : InteractiveUser;

            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] " +
                              $"RunAs: {processUser} | LoggedOn: {logonUser} | " +
                              $"Context: {context}, AdditionalInfo: {additionalInfo}, Message: {message}";

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(logFilePath)!);
                File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to write to log file: {ex.Message}");
            }
        }

        private static string GetCurrentUsername()
        {
            try
            {
                return WindowsIdentity.GetCurrent().Name;
            }
            catch
            {
                return "Unknown";
            }
        }
    }

    public enum LogLevel
    {
        INFO,
        WARNING,
        ERROR
    }
}
