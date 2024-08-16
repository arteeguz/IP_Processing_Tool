using System;
using System.IO;

namespace IPProcessingTool
{
    public static class Logger
    {
        private static readonly string logFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "log.txt");
        // private static readonly string logFilePath = @"\\netapp2b\DSS Interns\IP_Scanner\log.txt";

        public static void Log(LogLevel level, string message, string user = "System", string context = "", string additionalInfo = "")
        {
            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] User: {user}, Context: {context}, Additional Info: {additionalInfo}, Message: {message}";
            WriteLog(logEntry);
        }

        private static void WriteLog(string logEntry)
        {
            try
            {
                using (var writer = new StreamWriter(logFilePath, true))
                {
                    writer.WriteLine(logEntry);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to write log: {ex.Message}");
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