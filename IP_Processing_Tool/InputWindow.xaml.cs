using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace IPProcessingTool
{
    public partial class InputWindow : Window, INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        private Brush _inputTextBoxBorderBrush = Brushes.Gray;
        public Brush InputTextBoxBorderBrush
        {
            get => _inputTextBoxBorderBrush;
            set
            {
                _inputTextBoxBorderBrush = value;
                OnPropertyChanged(nameof(InputTextBoxBorderBrush));
            }
        }

        private string _inputTextBoxToolTip;
        public string InputTextBoxToolTip
        {
            get => _inputTextBoxToolTip;
            set
            {
                _inputTextBoxToolTip = value;
                OnPropertyChanged(nameof(InputTextBoxToolTip));
            }
        }

        private string _errorMessage;
        public string ErrorMessage
        {
            get => _errorMessage;
            set
            {
                _errorMessage = value;
                OnPropertyChanged(nameof(ErrorMessage));
            }
        }

        public string InputText { get; private set; }
        private bool isSegment;

        public InputWindow(string labelText, bool isSegment = false)
        {
            InitializeComponent();
            DataContext = this;

            InputLabel.Content = labelText;
            InputTextBox.TextChanged += InputTextBox_TextChanged;
            InputTextBox.PreviewTextInput += InputTextBox_PreviewTextInput;
            InputTextBox.PreviewKeyDown += InputTextBox_PreviewKeyDown;
            this.isSegment = isSegment;

            // Update IP count display
            UpdateIPCountLabel();

            // Set up keyboard shortcuts
            AddKeyboardShortcuts();
        }

        private void AddKeyboardShortcuts()
        {
            // Ctrl+V for paste handling - already works natively but we'll look for it
            // to provide visual feedback
            InputWindow window = this;
            window.KeyDown += (s, e) => {
                if (e.Key == Key.V && Keyboard.Modifiers == ModifierKeys.Control)
                {
                    // The default paste behavior will trigger the TextChanged event
                    ErrorMessage = "Processing paste...";
                }
            };

            // Handle Ctrl+A to select all text in InputTextBox
            InputTextBox.KeyDown += (s, e) => {
                if (e.Key == Key.A && Keyboard.Modifiers == ModifierKeys.Control)
                {
                    InputTextBox.SelectAll();
                    e.Handled = true;
                }
            };
        }

        private void InputTextBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            // Add support for Enter key to add the current IP
            if (e.Key == Key.Enter)
            {
                AddButton_Click(sender, e);
                e.Handled = true;
            }
        }

        private void InputTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string input = InputTextBox.Text;

            // Check if the input contains line breaks or multiple IPs separated by common delimiters
            if (ContainsMultipleIPs(input))
            {
                // We have a bulk paste operation - process it
                ProcessBulkInput(input);
                return;
            }

            int caretIndex = InputTextBox.CaretIndex;

            // Only format if we're adding characters, not deleting
            if (e.Changes.Any(change => change.AddedLength > 0))
            {
                (input, caretIndex) = FormatInputWithDots(input, caretIndex);
            }

            InputTextBox.Text = input;
            InputTextBox.CaretIndex = caretIndex;

            ValidateInput();
        }

        private bool ContainsMultipleIPs(string input)
        {
            // Excel content typically contains line breaks, but we'll check all common delimiters
            if (input.Contains('\n') || input.Contains('\r') ||
                input.Contains(Environment.NewLine) ||
                input.Contains(",") ||
                input.Contains(";") ||
                input.Contains("\t"))
            {
                return true;
            }

            return false;
        }

        private void UpdateIPCountLabel()
        {
            int count = IPListBox.Items.Count;
            IPCountLabel.Text = $"Total IPs in list: {count}";
        }

        private void ProcessBulkInput(string input)
        {
            // Split the input with various delimiters including Excel's line break formats
            string[] delimiters = new[] { "\r\n", "\r", "\n", ",", ";", "\t" };
            string[] potentialIPs = input.Split(delimiters, StringSplitOptions.RemoveEmptyEntries);

            int validCount = 0;
            int invalidCount = 0;

            foreach (string ip in potentialIPs)
            {
                string trimmedIP = ip.Trim();
                if (string.IsNullOrWhiteSpace(trimmedIP))
                    continue;

                (bool isValid, string errorMessage) = isSegment ? ValidateIPSegment(trimmedIP) : ValidateIP(trimmedIP);

                if (isValid)
                {
                    IPListBox.Items.Add(trimmedIP);
                    validCount++;
                }
                else
                {
                    invalidCount++;
                    Logger.Log(LogLevel.WARNING, $"Invalid {(isSegment ? "IP segment" : "IP address")}: {trimmedIP}",
                        context: "ProcessBulkInput", additionalInfo: errorMessage);
                }
            }

            // Clear the text box after processing
            InputTextBox.Clear();

            // Update IP count label
            UpdateIPCountLabel();

            // Update status message
            if (validCount > 0 && invalidCount == 0)
            {
                ErrorMessage = $"{validCount} valid {(isSegment ? "IP segments" : "IP addresses")} added successfully.";
                InputTextBoxBorderBrush = Brushes.Green;
            }
            else if (validCount > 0 && invalidCount > 0)
            {
                ErrorMessage = $"{validCount} valid and {invalidCount} invalid entries found. Only valid entries were added.";
                InputTextBoxBorderBrush = Brushes.Orange;
            }
            else if (validCount == 0 && invalidCount > 0)
            {
                ErrorMessage = $"No valid {(isSegment ? "IP segments" : "IP addresses")} found in pasted content.";
                InputTextBoxBorderBrush = Brushes.Red;
            }
        }

        private (string formattedInput, int newCaretIndex) FormatInputWithDots(string input, int caretIndex)
        {
            string[] parts = input.Split('.');
            string formattedInput = "";
            int newCaretIndex = caretIndex;
            int maxParts = isSegment ? 3 : 4;

            for (int i = 0; i < parts.Length && i < maxParts; i++)
            {
                if (parts[i].Length > 3)
                {
                    parts[i] = parts[i].Substring(0, 3);
                }

                int oldLength = formattedInput.Length;
                formattedInput += parts[i];

                if (i < maxParts - 1 && (parts[i].Length == 3 || i < parts.Length - 1))
                {
                    formattedInput += ".";
                }

                // Adjust caret index if a dot was added
                if (caretIndex > oldLength && formattedInput.Length > oldLength + parts[i].Length)
                {
                    newCaretIndex++;
                }
            }

            // Ensure caret doesn't go beyond the end of the input
            newCaretIndex = Math.Min(newCaretIndex, formattedInput.Length);

            return (formattedInput, newCaretIndex);
        }

        private void InputTextBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            string currentText = InputTextBox.Text;
            int dotCount = currentText.Count(c => c == '.');
            bool isNumberOrDot = Regex.IsMatch(e.Text, "[0-9.]");

            // Prevent further input if it's a dot and there are already 2 dots (for segments), or if it's not a valid character
            if ((e.Text == "." && dotCount >= (isSegment ? 2 : 3)) || !isNumberOrDot)
            {
                e.Handled = true;
            }
        }

        private void ValidateInput()
        {
            string input = InputTextBox.Text.Trim();
            (bool isValid, string errorMessage) = isSegment ? ValidateIPSegment(input) : ValidateIP(input);

            if (isValid)
            {
                InputTextBoxBorderBrush = Brushes.Gray;
                InputTextBoxToolTip = null;
                ErrorMessage = null;
            }
            else
            {
                InputTextBoxBorderBrush = Brushes.Red;
                ErrorMessage = errorMessage;
                InputTextBoxToolTip = errorMessage;
            }
        }

        private (bool isValid, string errorMessage) ValidateIP(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return (false, "Input cannot be empty.");

            if (!IPAddress.TryParse(ip, out _))
                return (false, "Invalid IP address format.");

            string[] parts = ip.Split('.');
            if (parts.Length != 4)
                return (false, "IP address must have four parts separated by dots.");

            foreach (var part in parts)
            {
                if (!byte.TryParse(part, out byte b))
                    return (false, $"'{part}' is not a valid number between 0 and 255.");
            }

            return (true, null);
        }

        private (bool isValid, string errorMessage) ValidateIPSegment(string segment)
        {
            if (string.IsNullOrWhiteSpace(segment))
                return (false, "Input cannot be empty.");

            string[] parts = segment.Split('.');
            if (parts.Length != 3)
                return (false, "IP segment must have exactly three parts separated by dots.");

            foreach (var part in parts)
            {
                if (!byte.TryParse(part, out byte b))
                    return (false, $"'{part}' is not a valid number between 0 and 255.");
            }

            return (true, null);
        }

        private void PasteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Get clipboard content
                if (Clipboard.ContainsText())
                {
                    string clipboardText = Clipboard.GetText();

                    // Process the clipboard content directly
                    if (!string.IsNullOrWhiteSpace(clipboardText))
                    {
                        ProcessBulkInput(clipboardText);
                    }
                }
                else
                {
                    ErrorMessage = "No text content found in clipboard.";
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error accessing clipboard: {ex.Message}";
                Logger.Log(LogLevel.ERROR, $"Clipboard access error: {ex.Message}", context: "PasteButton_Click");
            }
        }

        private void AddButton_Click(object sender, RoutedEventArgs e)
        {
            string input = InputTextBox.Text.Trim();
            (bool isValid, string errorMessage) = isSegment ? ValidateIPSegment(input) : ValidateIP(input);

            if (isValid)
            {
                IPListBox.Items.Add(input);
                InputTextBox.Clear();
                InputTextBoxBorderBrush = Brushes.Gray;
                InputTextBoxToolTip = null;
                ErrorMessage = null;
            }
            else
            {
                InputTextBoxBorderBrush = Brushes.Red;
                ErrorMessage = errorMessage;
                InputTextBoxToolTip = errorMessage;
                MessageBox.Show(errorMessage, "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void Submit_Click(object sender, RoutedEventArgs e)
        {
            if (IPListBox.Items.Count > 0)
            {
                InputText = string.Join(Environment.NewLine, IPListBox.Items.Cast<string>());
                DialogResult = true;
                Close();
            }
            else
            {
                MessageBox.Show("No IPs added. Please enter at least one IP address or segment.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Back_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void ClearList_Click(object sender, RoutedEventArgs e)
        {
            if (IPListBox.Items.Count > 0)
            {
                var result = MessageBox.Show($"Are you sure you want to clear all {IPListBox.Items.Count} items?",
                    "Confirm Clear", MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    IPListBox.Items.Clear();
                    ErrorMessage = "List cleared.";
                }
            }
            else
            {
                ErrorMessage = "List is already empty.";
            }
        }

        protected void OnPropertyChanged(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}