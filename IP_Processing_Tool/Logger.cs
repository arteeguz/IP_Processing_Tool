using System;
using System.IO;
using System.Security.Principal;

namespace IPProcessingTool
{
    public static class Logger
    {
        private static readonly string logFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "IPProcessingTool", "app.log");

        public static void Log(LogLevel level, string message, string context = "", string additionalInfo = "")
        {
            string username = GetCurrentUsername();
            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] User: {username}, Context: {context}, Additional Info: {additionalInfo}, Message: {message}";

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
            catch (Exception)
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