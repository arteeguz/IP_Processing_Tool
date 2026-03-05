# IP Processing Tool — Improvement Plan

**Branch:** `UI_Scan`
**Target OS:** Windows 11 23H2 (Build 22631.6649)
**Date:** 2026-03-04

---

## Table of Contents
1. [Bugs & Correctness Issues](#1-bugs--correctness-issues)
2. [Windows 23H2 Compatibility](#2-windows-23h2-compatibility)
3. [Performance](#3-performance)
4. [UI / UX](#4-ui--ux)
5. [Code Quality & Dead Code](#5-code-quality--dead-code)
6. [Missing Features](#6-missing-features)

---

## 1. Bugs & Correctness Issues

### 1.1 `GetWindowsReleaseIdAsync` — broken WMI loop

**Problem:** The function queries `Win32_Registry` (an unrelated WMI class) and only opens the remote registry key *inside* the loop. If `Win32_Registry` returns zero results, the registry is never read and the function always returns `"Unknown"`.

**Before:**
```csharp
var query = new ObjectQuery(@"SELECT * FROM Win32_Registry");
using var searcher = new ManagementObjectSearcher(scope, query);
var registryEntries = await Task.Run(() => searcher.Get(), cancellationToken);

foreach (ManagementObject registryEntry in registryEntries)  // may be empty
{
    using var baseKey = RegistryKey.OpenRemoteBaseKey(...);
    ...
}
```

**Fix:** Remove the WMI query entirely. Open the remote registry key directly.
```csharp
private async Task<string> GetWindowsReleaseIdAsync(ManagementScope scope, CancellationToken cancellationToken)
{
    return await Task.Run(() =>
    {
        try
        {
            using var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, scope.Path.Server);
            using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key == null) return "Unknown";

            return key.GetValue("DisplayVersion") as string
                ?? key.GetValue("ReleaseId") as string
                ?? "Unknown";
        }
        catch { return "Unknown"; }
    }, cancellationToken);
}
```

---

### 1.2 `GetMachineModelAsync` — wrong WMI property

**Problem:** Queries `Win32_ComputerSystemProduct.Version`, which is blank or generic on most modern hardware (e.g., returns `"None"` or `"System Version"` on Dell/HP/Lenovo).

**Before:**
```csharp
var modelQuery = new ObjectQuery("SELECT Version FROM Win32_ComputerSystemProduct");
scanStatus.MachineModel = model["Version"]?.ToString() ?? "N/A";
```

**Fix:** Use `Win32_ComputerSystem.Model` which reliably returns the human-readable model name (e.g., `"HP EliteBook 840 G9"`).
```csharp
var modelQuery = new ObjectQuery("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
// model["Manufacturer"] + " " + model["Model"]  →  "HP EliteBook 840 G9"
```

---

### 1.3 `GetLastLoggedUserAsync` — returns *current* user, not *last* user

**Problem:** `Win32_ComputerSystem.UserName` returns the user currently logged in interactively. If no user is logged in the field is null/empty. It does not return the last logged-in user.

**Before:**
```csharp
var userQuery = new ObjectQuery("SELECT UserName FROM Win32_ComputerSystem");
scanStatus.LastLoggedUser = user["UserName"]?.ToString() ?? "N/A";
```

**Fix:** Read the last logged-in user from the remote registry key `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\LastLoggedOnUser`, which persists across logouts.
```csharp
using var baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ip);
using var key = baseKey.OpenSubKey(
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
scanStatus.LastLoggedUser = key?.GetValue("LastLoggedOnUser") as string ?? "N/A";
```

---

### 1.4 `GetBIOSInfoAsync` — three WMI queries for one class

**Problem:** Makes three separate round-trip WMI queries to `Win32_BIOS` to get BIOS info, SMBIOS version, and EC version, when all fields can be fetched in a single query.

**Before:**
```csharp
// Query 1 — BIOS info
var biosQuery = new ObjectQuery("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
// Query 2 — SMBIOS version
var smbiosQuery = new ObjectQuery("SELECT SMBIOSMajorVersion, SMBIOSMinorVersion FROM Win32_BIOS");
// Query 3 — EC version
var ecQuery = new ObjectQuery("SELECT EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion FROM Win32_BIOS");
```

**Fix:** One query, all fields.
```csharp
var biosQuery = new ObjectQuery(
    "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, " +
    "SMBIOSMajorVersion, SMBIOSMinorVersion, " +
    "EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion " +
    "FROM Win32_BIOS");
```

---

### 1.5 `GetNetworkAdaptersInfoAsync` — MAC address uses first physical adapter regardless of type

**Problem:** The MAC address is grabbed from the very first physical adapter, which could be a Bluetooth or Hyper-V virtual adapter on Windows 11. Should prefer the primary Ethernet adapter MAC.

**Before:**
```csharp
if (!macAddressSet && !string.IsNullOrEmpty(macAddress))
{
    scanStatus.MACAddress = macAddress;  // First physical adapter wins — could be Bluetooth
    macAddressSet = true;
}
```

**Fix:** Set MAC only from an enabled Ethernet or WiFi adapter; fall back to any physical adapter only if none found.

---

### 1.6 `UpdateScanStatus` — `Items.Refresh()` on every result

**Problem:** `StatusDataGrid.Items.Refresh()` forces a full UI rebind of every row. Called once per completed IP scan, this causes the grid to freeze visibly when scanning hundreds of IPs. `ObservableCollection` already notifies the grid of changes.

**Before:**
```csharp
private void UpdateScanStatus(ScanStatus scanStatus)
{
    Dispatcher.Invoke(() =>
    {
        ...
        ScanStatuses[index] = scanStatus;  // Already triggers UI update
        StatusDataGrid.Items.Refresh();    // Redundant, causes lag
    });
}
```

**Fix:** Remove the `Items.Refresh()` call entirely.

---

### 1.7 Logger hardcoded to Desktop

**Problem:** Log file path is hardcoded to the user's Desktop. On managed/locked-down machines this path may be redirected or restricted, silently swallowing all log writes.

**Before:**
```csharp
private static readonly string logFilePath =
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "log.txt");
```

**Fix:** Use `%APPDATA%\IPProcessingTool\` with a fallback to `AppDomain.CurrentDomain.BaseDirectory`. Make the path configurable via settings.

---

## 2. Windows 23H2 Compatibility

### 2.1 `DisplayVersion` vs `ReleaseId` (covered in fix 1.1)

On Windows 11 23H2, `ReleaseId` in the registry is frozen at `"2009"` (a legacy artefact). `DisplayVersion` is the correct key and returns `"23H2"`. The fix in §1.1 already prefers `DisplayVersion`.

### 2.2 Embedded Controller version — VMs return `255.255`

On Hyper-V and VMware guests running 23H2, `EmbeddedControllerMajorVersion` = 255 and `EmbeddedControllerMinorVersion` = 255. This should be displayed as `"N/A (Virtual)"` rather than `"255.255"`.

**Fix:**
```csharp
if (ecMajor == 255 && ecMinor == 255)
    scanStatus.EmbeddedControllerVersion = "N/A (Virtual)";
else
    scanStatus.EmbeddedControllerVersion = $"{ecMajor}.{ecMinor}";
```

### 2.3 `Win32_NetworkAdapter` — Microsoft Kernel Debug network adapter

On Windows 11 23H2 developer machines, `PhysicalAdapter=True` also captures the Microsoft Kernel Debug Network Adapter. Filter it out by manufacturer:

```csharp
// Add to WMI filter:
"SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True AND Manufacturer != 'Microsoft'"
```

### 2.4 Office detection — missing 32-bit on 64-bit OS registry path

**Problem:** `GetOfficeVersionAsync` opens `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` via `OpenRemoteBaseKey`. On a 64-bit OS this opens the 64-bit view. If a 32-bit Office is installed (legacy), it lives at `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` instead.

**Fix:** Also check the WOW6432Node path as a fallback when nothing is found in the 64-bit key. Microsoft 365 (64-bit) is found correctly as-is.

---

## 3. Performance

### 3.1 Hostname resolution is sequential

**Problem:** Hostnames are resolved one-by-one with `await` in a `foreach` loop before scanning begins. For 100 hostnames this adds significant wall-clock delay before any scans start.

**Before:**
```csharp
foreach (var entry in ipsOrHostnames)
{
    var resolvedIP = await ResolveHostnameToIPAsync(entry);  // Sequential
    ...
}
```

**Fix:** Resolve all hostnames in parallel with `Task.WhenAll`.
```csharp
var resolutionTasks = ipsOrHostnames.Select(e => ResolveHostnameToIPAsync(e));
var resolved = await Task.WhenAll(resolutionTasks);
```

### 3.2 Three WMI queries → one (covered in fix 1.4)

Reduces per-host scan time measurably on high-latency LAN connections.

### 3.3 Port scan timeout is hardcoded

**Problem:** `IsPortOpenAsync` uses a hardcoded 2-second timeout. If 7 ports are checked per IP, this adds up to 14 seconds worst-case per host just waiting for closed ports.

**Fix:** Make port timeout configurable in Settings (default: 1000 ms). Expose it alongside the existing ping timeout.

### 3.4 `StatusDataGrid.Items.Refresh()` on every row update (covered in fix 1.6)

Removing this alone significantly improves UI responsiveness during large scans.

---

## 4. UI / UX

### 4.1 Progress bar shows no percentage

**Before:** Plain empty `<ProgressBar>` — no text, no count.

**Fix:** Overlay a `TextBlock` on the progress bar showing `"47 / 200 (23%)"`.
```xml
<Grid Grid.Row="2">
    <ProgressBar Name="ProgressBar" Height="20" Margin="10"/>
    <TextBlock Name="ProgressText" HorizontalAlignment="Center"
               VerticalAlignment="Center" FontSize="11" Foreground="White"/>
</Grid>
```

### 4.2 Action buttons in StatusBar

**Before:** Save, Rescan, Stop, Clear, WoL buttons are crammed inside the `<StatusBar>` at the bottom. This is non-standard and they have inconsistent heights.

**Fix:** Move them to a `<ToolBar>` below the header or a dedicated button row above the DataGrid. Keep the StatusBar for text-only status messages.

### 4.3 No scan summary in status bar

**Before:** Status bar shows `"Completed processing all IPs."` only.

**Fix:** Show counts: `"Done — 142 Online | 28 Offline | 5 Errors | 25 Unreachable"` after scan completion.

### 4.4 No search / filter for the results grid

**Fix:** Add a `TextBox` above the DataGrid. Use a `CollectionViewSource` with a filter predicate that matches any column.

### 4.5 Settings not persisted between sessions

**Before:** Every setting (ping timeout, concurrent scans, column visibility) resets to defaults when the app closes.

**Fix:** Save to `%APPDATA%\IPProcessingTool\settings.json` on OK, load on startup. Use `System.Text.Json` (already in .NET 8).

### 4.6 Floor mappings are hardcoded

**Before:** `InitializeFloorMappings()` has a hardcoded dictionary in `MainWindow.xaml.cs`.

**Fix:** Load from an editable `floor_mappings.json` file placed alongside the executable. Fall back to built-in defaults if the file is not found.

---

## 5. Code Quality & Dead Code

### 5.1 Dead fields: `_batch` and `BATCH_SIZE`

`_batch` (a `List<ScanStatus>`) and `BATCH_SIZE = 50` are declared but never written to or read from anywhere in the codebase.

**Fix:** Delete both.

### 5.2 Dead methods in `MainWindow.xaml.cs`

The following methods exist but are never called from any UI path:
- `IsValidIPSegment` — duplicate of `IsIPSegment` in `ModernInputWindow`
- `HighlightInvalidInput`
- `ShowInvalidInputMessage`

**Fix:** Delete all three.

### 5.3 Column binding uses fragile string replace

**Problem:** `column.Name.Replace(" ", "")` is used to generate the property binding path and in `GetPropertyValue`. A column rename or a property rename breaks the binding silently with no compile-time error.

**Before:**
```csharp
Binding = new Binding(column.Name.Replace(" ", ""))
```

**Fix:** Add an explicit `PropertyName` to `ColumnSetting` that maps directly to the `ScanStatus` property name. This makes the mapping explicit and rename-safe.
```csharp
public class ColumnSetting
{
    public string Name { get; set; }          // Display name
    public string PropertyName { get; set; }  // ScanStatus property name
    public bool IsSelected { get; set; }
}
```

### 5.4 `ShowSuccessMessage()` is empty

`Settings.xaml.cs` has a `ShowSuccessMessage()` method with only a comment inside. It is never called.

**Fix:** Delete it, or implement a brief status label in the settings window.

### 5.5 `ScanStatus` class defined inside `MainWindow`

`ScanStatus` and `ColumnSetting` / `ColumnSettingComparer` are nested inside other classes. This makes them harder to find and reuse.

**Fix:** Move each to its own file: `ScanStatus.cs`, `ColumnSetting.cs`.

---

## 6. Missing Features

| # | Feature | Notes |
|---|---------|-------|
| 6.1 | **Export to XLSX** | Add Excel export using `ClosedXML` NuGet package (MIT licensed) |
| 6.2 | **Export to JSON** | Useful for downstream tooling; trivial with `System.Text.Json` |
| 6.3 | **Results filter / search** | See §4.4 |
| 6.4 | **Per-host scan detail popup** | Double-click a row → modal with full info + raw WMI output |
| 6.5 | **Configurable port list** | Currently fixed to 7 ports; allow adding custom ports in Settings |
| 6.6 | **Scan history** | Save/load previous scan sessions from JSON files |
| 6.7 | **Dark mode** | WPF resource dictionary swap; toggle in Settings |

---

## Summary — Priority Order

| Priority | Item | Impact |
|----------|------|--------|
| **P1 — Fix now** | 1.1 `GetWindowsReleaseIdAsync` bug | Always returns `"Unknown"` on 23H2 |
| **P1 — Fix now** | 1.3 `GetLastLoggedUserAsync` wrong field | Returns current user, not last user |
| **P1 — Fix now** | 1.2 `GetMachineModelAsync` wrong property | Returns blank on most hardware |
| **P1 — Fix now** | 1.6 `Items.Refresh()` on every update | UI freeze during large scans |
| **P2 — Soon** | 3.1 Sequential hostname resolution | Adds unnecessary delay upfront |
| **P2 — Soon** | 1.4 BIOS triple WMI query | 3× network round trips for one task |
| **P2 — Soon** | 4.5 Settings persistence | Users lose all config on restart |
| **P3 — Nice** | 4.3 Scan summary counts | Better at-a-glance results |
| **P3 — Nice** | 4.1 Progress bar percentage | Basic UX improvement |
| **P3 — Nice** | 5.1–5.5 Dead code cleanup | Maintainability |
| **P4 — Later** | 6.x New features | Enhancements |
