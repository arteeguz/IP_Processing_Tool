# IP Processing Tool — Developer Guide

**Version:** 10.0.0
**Branch:** `feat/v10.0.0`
**Target OS:** Windows 11 23H2 (Build 22631.6649)
**Framework:** .NET 8 WPF (Windows-only)
**Last updated:** 2026-03-04

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Architecture & Data Flow](#3-architecture--data-flow)
4. [Feature Deep-Dives](#4-feature-deep-dives)
   - 4.1 [Settings Persistence — How & Where](#41-settings-persistence--how--where)
   - 4.2 [Floor Mappings — How They Work](#42-floor-mappings--how-they-work)
   - 4.3 [Scan Workflow — End to End](#43-scan-workflow--end-to-end)
   - 4.4 [NIC Detection — Ethernet vs Wi-Fi](#44-nic-detection--ethernet-vs-wi-fi)
   - 4.5 [Column Visibility System](#45-column-visibility-system)
   - 4.6 [Sort & Filter on the Results Grid](#46-sort--filter-on-the-results-grid)
   - 4.7 [Wake-on-LAN](#47-wake-on-lan)
   - 4.8 [Logger](#48-logger)
   - 4.9 [Input Window & Target Parsing](#49-input-window--target-parsing)
   - 4.10 [Progress Bar & Status Bar](#410-progress-bar--status-bar)
5. [Key Classes & Files](#5-key-classes--files)
6. [WMI Queries Reference](#6-wmi-queries-reference)
7. [Changelog — Every Commit Explained](#7-changelog--every-commit-explained)
8. [Common Pitfalls & Why We Fixed Them](#8-common-pitfalls--why-we-fixed-them)
9. [How to Extend the Tool](#9-how-to-extend-the-tool)

---

## 1. Project Overview

The IP Processing Tool is an internal RBC Capital Markets desktop application.
Given a list of IP addresses, hostnames, CIDR ranges, or IP segments, it:

- Pings each target to determine reachability
- Queries the target machine via **WMI** (Windows Management Instrumentation) over the network
- Queries the target machine's **remote registry** for data WMI cannot access
- Checks common ports (RDP, WMI, SMB, etc.) to determine connectivity
- Presents all results in a sortable, filterable data grid
- Exports results to CSV
- Sends **Wake-on-LAN** packets to sleeping machines
- Maps IP addresses to physical building **floors**

All network queries are async and run in parallel (bounded by a configurable semaphore).

---

## 2. Repository Layout

```
IP_Processing_Tool/
│
├── IMPROVEMENTS.md              ← Original improvement plan (bugs found + before/after fixes)
├── DEVELOPER_GUIDE.md           ← This file
│
└── IP_Processing_Tool/          ← C# project
    ├── App.xaml / App.xaml.cs   ← WPF app entry point; nothing custom here
    ├── AssemblyInfo.cs          ← Assembly metadata
    │
    ├── MainWindow.xaml          ← Main window layout (header, toolbar, search bar, grid, progress, status)
    ├── MainWindow.xaml.cs       ← All scan logic, WMI queries, settings load/save, grid management
    │
    ├── ModernInputWindow.xaml   ← "Start Scan" dialog — enter targets or upload file
    ├── ModernInputWindow.xaml.cs← Target parsing (IP, range, CIDR, hostname, segment)
    │
    ├── Settings.xaml            ← Settings dialog layout
    ├── Settings.xaml.cs         ← Settings dialog logic; exposes typed properties
    │
    ├── AppSettings.cs           ← JSON persistence model (read/write settings.json)
    ├── Logger.cs                ← File logger → %APPDATA%\IPProcessingTool\app.log
    ├── WOL.cs                   ← Wake-on-LAN UDP broadcast
    │
    └── images/
        └── RBC-Logo.png         ← Header logo
```

**Runtime files** (placed next to the `.exe` after build):

| File | Purpose |
|------|---------|
| `floor_mappings.json` | Optional — overrides built-in IP→floor mapping. If absent, defaults are used. |

**Per-user data** (written automatically at runtime):

| Path | Purpose |
|------|---------|
| `%APPDATA%\IPProcessingTool\settings.json` | Persisted settings (timeouts, column visibility, auto-save) |
| `%APPDATA%\IPProcessingTool\app.log` | Application log |

---

## 3. Architecture & Data Flow

```
User clicks "Start Scan"
        │
        ▼
ModernInputWindow (dialog)
  └─ ParseInput() → List<string> targets
        │
        ▼
MainWindow.ScanButton_Click()
  └─ Opens ModernInputWindow, gets ProcessedTargets
        │
        ▼
StartScanAsync(targets)
  ├─ Parallel hostname resolution  (Task.WhenAll)
  ├─ Creates one ScanStatus per target (shown immediately as "Scanning...")
  ├─ SemaphoreSlim(MaxConcurrentScans)  ← throttle
  └─ For each IP, fires ScanIPAsync(ip, cancellationToken)
            │
            ▼
      ScanIPAsync()
        ├─ PingAsync()                    → Status = Online/Offline
        ├─ GetWindowsReleaseIdAsync()     → WindowsVersion (registry)
        ├─ GetLastLoggedUserAsync()       → LastLoggedUser (registry)
        ├─ GetMachineModelAsync()         → MachineModel (WMI)
        ├─ GetBIOSInfoAsync()             → BIOSVersion, SMBIOSVersion, ECVersion (WMI)
        ├─ GetNetworkAdaptersInfoAsync()  → NIC0LAN…NIC3, MACAddress (WMI)
        ├─ GetRAMInfoAsync()              → RAMSize (WMI)
        ├─ GetOfficeVersionAsync()        → OfficeVersion (registry, 64+32-bit)
        ├─ GetDiskInfoAsync()             → DiskSize, FreeSpace (WMI)
        ├─ CheckPortsAsync()              → open port list (TCP connect)
        ├─ GetFloorForIP()               → Floor (in-memory dictionary)
        └─ UpdateScanStatus()            → updates ObservableCollection → grid refreshes via binding
```

The `ObservableCollection<ScanStatus>` is the single source of truth.
The DataGrid binds to an `ICollectionView` wrapping that collection so sort and filter work without touching the collection itself.

---

## 4. Feature Deep-Dives

---

### 4.1 Settings Persistence — How & Where

#### The Problem (before v10.0.0)

Every time the app closed, all settings reset to defaults. Users had to reconfigure ping timeout, thread count, and column visibility every session.

#### How It Works Now

**Step 1 — App starts → `MainWindow` constructor calls `LoadPersistedSettings()`**

```csharp
// MainWindow.xaml.cs
private void LoadPersistedSettings()
{
    var saved = AppSettings.Load();                         // reads the JSON file
    if (saved.PingTimeout > 0) pingTimeout = saved.PingTimeout;
    if (saved.MaxConcurrentScans > 0) MaxConcurrentScans = saved.MaxConcurrentScans;
    if (saved.ExecutionTimeLimit > 0) ExecutionTimeLimit = saved.ExecutionTimeLimit;
    autoSave = saved.AutoSave;

    // Restore column visibility by matching PropertyName (not display Name)
    foreach (var savedCol in saved.Columns)
    {
        var match = dataColumnSettings.FirstOrDefault(c => c.PropertyName == savedCol.PropertyName);
        if (match != null) match.IsSelected = savedCol.IsSelected;
    }
}
```

**Step 2 — User opens Settings, changes values, clicks "Save Settings"**

Settings dialog closes with `DialogResult = true`, then back in `MainWindow`:

```csharp
// MainWindow.xaml.cs → SettingsButton_Click
autoSave    = settingsWindow.AutoSave;
pingTimeout = settingsWindow.PingTimeout;
MaxConcurrentScans   = settingsWindow.MaxConcurrentScans;
ExecutionTimeLimit   = settingsWindow.ExecutionTimeLimit;

SavePersistedSettings();   // immediately writes to disk
```

**Step 3 — `SavePersistedSettings()` serialises to JSON**

```csharp
private void SavePersistedSettings()
{
    var settings = new AppSettings
    {
        PingTimeout        = pingTimeout,
        MaxConcurrentScans = MaxConcurrentScans,
        ExecutionTimeLimit = ExecutionTimeLimit,
        AutoSave           = autoSave,
        Columns = dataColumnSettings.Select(c => new ColumnSettingData
        {
            Name         = c.Name,
            PropertyName = c.PropertyName,
            IsSelected   = c.IsSelected
        }).ToList()
    };
    settings.Save();   // → AppSettings.cs
}
```

**Step 4 — `AppSettings.Save()` writes to disk**

```csharp
// AppSettings.cs
private static readonly string SettingsPath =
    Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "IPProcessingTool",
        "settings.json");

public void Save()
{
    Directory.CreateDirectory(SettingsDir);   // creates folder if missing
    var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(SettingsPath, json);
}
```

#### Where the file lives

```
C:\Users\<username>\AppData\Roaming\IPProcessingTool\settings.json
```

You can open `%APPDATA%\IPProcessingTool\settings.json` in any text editor to inspect or manually reset settings.

#### What the file looks like

```json
{
  "PingTimeout": 1500,
  "MaxConcurrentScans": 20,
  "ExecutionTimeLimit": 90,
  "AutoSave": false,
  "Columns": [
    { "Name": "IP Address",   "PropertyName": "IPAddress",   "IsSelected": true  },
    { "Name": "Status",       "PropertyName": "Status",      "IsSelected": true  },
    { "Name": "Floor",        "PropertyName": "Floor",       "IsSelected": true  },
    { "Name": "NIC 0 (LAN)",  "PropertyName": "NIC0LAN",    "IsSelected": true  },
    { "Name": "NIC 1 (WiFi)", "PropertyName": "NIC1WiFi",   "IsSelected": false },
    ...
  ]
}
```

#### What happens if the file is missing or corrupt

`AppSettings.Load()` catches all exceptions and returns a `new AppSettings()` with hard-coded defaults. The app always starts successfully.

---

### 4.2 Floor Mappings — How They Work

#### What is a "floor mapping"?

RBC uses structured IP subnets to assign blocks of addresses to physical office floors. The third octet of the IP address (`x.x.OCTET.x`) identifies which floor a machine is on.

For example:
- `10.9.115.42` → third octet is `115` → segment `10.9.115` → **"30 Hudson 20 east"**
- `10.9.116.7`  → segment `10.9.116` → **"30 Hudson 20 west"**

#### The Lookup

`GetFloorForIP(ipAddress)` in `MainWindow.xaml.cs`:

```csharp
private string GetFloorForIP(string ipAddress)
{
    string[] parts = ipAddress.Split('.');
    if (parts.Length >= 3)
    {
        string segment = $"{parts[0]}.{parts[1]}.{parts[2]}";   // "10.9.115"
        if (floorMappings.TryGetValue(segment, out string floor))
            return floor;                                         // "30 Hudson 20 east"
    }
    return "Unknown";
}
```

This runs in memory — no WMI, no network call. It's instant.

#### Where the mapping data comes from

**Priority 1 — External file** (`floor_mappings.json` next to the `.exe`):

```json
{
  "10.9.115": "30 Hudson 20 east",
  "10.9.116": "30 Hudson 20 west",
  "10.9.97":  "30 Hudson 25 west"
}
```

If this file exists and is valid JSON, it completely replaces the built-in defaults.

**Priority 2 — Built-in defaults** (compiled into the application):

```csharp
// MainWindow.xaml.cs
private static readonly Dictionary<string, string> DefaultFloorMappings = new()
{
    { "10.9.115", "30 Hudson 20 east" },
    { "10.9.116", "30 Hudson 20 west" },
    { "10.9.97",  "30 Hudson 25 west" },
    { "10.9.107", "30 Hudson 25 west" },
    { "10.9.96",  "30 Hudson 25 east" },
    // ... 13 more entries
};
```

#### Startup sequence

```csharp
private void InitializeFloorMappings()
{
    string jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "floor_mappings.json");
    try
    {
        if (File.Exists(jsonPath))
        {
            var json = File.ReadAllText(jsonPath);
            floorMappings = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                            ?? new Dictionary<string, string>(DefaultFloorMappings);
            Logger.Log(LogLevel.INFO, $"Loaded floor mappings from {jsonPath}");
            return;
        }
    }
    catch (Exception ex)
    {
        Logger.Log(LogLevel.WARNING, $"Could not load floor_mappings.json: {ex.Message}. Using defaults.");
    }
    floorMappings = new Dictionary<string, string>(DefaultFloorMappings);
}
```

#### How to add a new floor

**Option A — Edit the JSON file** (no recompile needed):

1. Locate or create `floor_mappings.json` next to `IP_Processing_Tool.exe`
2. Add your entry: `"10.9.200": "Canary Wharf 3rd Floor"`
3. Restart the app

**Option B — Edit `DefaultFloorMappings`** in `MainWindow.xaml.cs` (requires recompile):

```csharp
{ "10.9.200", "Canary Wharf 3rd Floor" },
```

---

### 4.3 Scan Workflow — End to End

#### 1. User clicks "🔍 Start Scan"

`ScanButton_Click` opens `ModernInputWindow` as a dialog.

#### 2. User enters targets

Supported formats (parsed by `ModernInputWindow.xaml.cs`):

| Input | Expands to |
|-------|-----------|
| `192.168.1.5` | Single IP |
| `server01.company.com` | Hostname (resolved to IP before scanning) |
| `192.168.1.1-192.168.1.50` | 50 individual IPs |
| `192.168.1.0/24` | 256 IPs (network + broadcast included) |
| `192.168.1` | 256 IPs (.0 through .255) |

The dialog returns `ProcessedTargets: List<string>` — already expanded, always a flat list of strings (IPs or hostnames).

#### 3. Hostname resolution (parallel)

Before scanning, all hostnames in the list are resolved to IP addresses simultaneously:

```csharp
// Before v10.0.0 — sequential (slow)
foreach (var entry in targets)
    var ip = await ResolveHostnameToIPAsync(entry);  // blocks until each resolves

// After v10.0.0 — parallel (fast)
var tasks = targets.Select(e => ResolveHostnameToIPAsync(e));
var resolved = await Task.WhenAll(tasks);            // all resolve concurrently
```

Unresolvable hostnames keep their original string — the scan will show "Unreachable" for them.

#### 4. ScanStatus rows created

One `ScanStatus` object per target is added to `ScanStatuses` (ObservableCollection) immediately, showing `Status = "Scanning..."`. The grid shows rows appearing in real time.

#### 5. Parallel scan with throttle

```csharp
var semaphore = new SemaphoreSlim(MaxConcurrentScans);   // e.g. 20 concurrent

var tasks = ScanStatuses.Select(async s =>
{
    await semaphore.WaitAsync(ct);
    try   { await ScanIPAsync(s, ct); }
    finally { semaphore.Release(); }
});

await Task.WhenAll(tasks);
```

This means up to `MaxConcurrentScans` IPs are being queried simultaneously. The rest queue up.

#### 6. Per-IP scan (`ScanIPAsync`)

For each IP:

1. **Ping** — 3 attempts with `pingTimeout` ms each. If all fail → `Status = Offline`, remaining steps skipped.
2. **WMI scope** — opens `\\IP\root\cimv2` with the current user's credentials.
3. **Registry + WMI queries** — run with a `CancellationTokenSource` that fires after `ExecutionTimeLimit` seconds. If hit → `Status = Timeout`.
4. **Floor lookup** — instant dictionary lookup.
5. **`UpdateScanStatus()`** — dispatches to UI thread, updates the row in the ObservableCollection.

#### 7. Completion

After all tasks finish (or are cancelled):

- `UpdateProgressBar(100, total, total)` fills the bar
- `UpdateScanSummary()` writes "Done — X Online | Y Offline | Z Errors..." to the status bar
- `EnableButtons()` hides Stop, shows Clear, re-enables Start Scan
- If `autoSave = true`, CSV is written without prompting

---

### 4.4 NIC Detection — Ethernet vs Wi-Fi

#### The Problem (before v10.0.0)

The old code used `AdapterType` (a string like `"Ethernet 802.3"`) which is unreliable — some drivers report it differently or leave it blank. It also required `NetEnabled=True`, so disconnected (unplugged) adapters were invisible.

#### How It Works Now

Two WMI queries are made:

**Query 1 — Get IP addresses for connected adapters:**

```csharp
"SELECT IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"
```

This builds a dictionary: `MAC → List<IPAddress>`.

**Query 2 — Get all physical adapters (connected or not):**

```csharp
"SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True AND Manufacturer != 'Microsoft'"
```

Excluding `Manufacturer != 'Microsoft'` removes the Kernel Debug Network Adapter that Windows 11 exposes.

**Classification by `AdapterTypeId`:**

| `AdapterTypeId` | Meaning |
|----------------|---------|
| `0` | Ethernet (802.3) |
| `9` | Wireless (802.11) |
| `15` | Wireless WAN |
| anything else | Unknown |

If `AdapterTypeId` alone doesn't classify it, the adapter **name** is checked for keywords: `Wi-Fi`, `WiFi`, `Wireless`, `WLAN`, `802.11`.

**Slot assignment:**

```
NIC0LAN   ← first Ethernet adapter found
NIC1WiFi  ← first Wi-Fi adapter found
NIC2LAN2  ← second Ethernet adapter found (dual-NIC desktops)
NIC3      ← any fourth adapter (Wireless WAN, etc.)
```

**Display format:**

```
Intel I219-LM | MAC: 00:1A:2B:3C:4D:5E | IP: 10.9.115.42 | 1000 Mbps | Connected
```

If the adapter is disconnected (not in the `IPEnabled` query results), IP shows as `—` and speed shows as `—`.

---

### 4.5 Column Visibility System

#### The Classes

```csharp
// In MainWindow.xaml.cs
public class ColumnSetting
{
    public string Name { get; set; }          // Display label: "NIC 0 (LAN)"
    public string PropertyName { get; set; }  // ScanStatus property: "NIC0LAN"
    public bool IsSelected { get; set; }      // Visible in grid?
}
```

`Name` = what the user sees in Settings.
`PropertyName` = the exact C# property name on `ScanStatus` that the DataGrid column binds to.

#### Why `PropertyName` Was Added

**Before v10.0.0**, the binding path was generated by stripping spaces from the column name:

```csharp
Binding = new Binding(column.Name.Replace(" ", ""));   // "NIC 0 (LAN)" → "NIC0(LAN)" — WRONG
```

This silently broke whenever a display name didn't exactly match the property name. No compile-time error.

**After v10.0.0**, `nameof()` is used to assign `PropertyName` at initialization:

```csharp
new ColumnSetting { Name = "NIC 0 (LAN)",  PropertyName = nameof(ScanStatus.NIC0LAN),  IsSelected = true },
new ColumnSetting { Name = "NIC 1 (WiFi)", PropertyName = nameof(ScanStatus.NIC1WiFi), IsSelected = true },
```

`nameof()` is evaluated at compile time — if you rename the property and forget to update this list, the build fails.

#### How `UpdateDataGridColumns()` Uses It

```csharp
private void UpdateDataGridColumns()
{
    StatusDataGrid.Columns.Clear();
    foreach (var col in dataColumnSettings.Where(c => c.IsSelected))
    {
        StatusDataGrid.Columns.Add(new DataGridTextColumn
        {
            Header         = col.Name,
            Binding        = new Binding(col.PropertyName),   // e.g. "NIC0LAN"
            SortMemberPath = col.PropertyName,                // enables column header click-to-sort
        });
    }
    _scanView?.Refresh();
}
```

---

### 4.6 Sort & Filter on the Results Grid

#### Sort

Every column has `SortMemberPath = col.PropertyName` set (see above) and the DataGrid has `CanUserSortColumns="True"`. Clicking a column header sorts ascending; clicking again sorts descending. WPF handles this natively via the `ICollectionView`.

#### Filter

The grid's `ItemsSource` is not the `ObservableCollection` directly — it's an `ICollectionView` wrapping it:

```csharp
// MainWindow constructor
_scanView = CollectionViewSource.GetDefaultView(ScanStatuses);
_scanView.Filter = FilterRow;
StatusDataGrid.ItemsSource = _scanView;
```

When the user types in the search box:

```csharp
public void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
{
    _filterText = ((TextBox)sender).Text.Trim();
    _scanView.Refresh();       // re-runs FilterRow() on every row
    UpdateResultCount();       // updates "42 of 256 rows" label
}
```

`FilterRow()` checks every visible column's property on each row:

```csharp
private bool FilterRow(object obj)
{
    if (string.IsNullOrEmpty(_filterText)) return true;
    if (obj is not ScanStatus s) return false;

    foreach (var col in dataColumnSettings.Where(c => c.IsSelected))
    {
        var val = typeof(ScanStatus).GetProperty(col.PropertyName)?.GetValue(s)?.ToString() ?? "";
        if (val.IndexOf(_filterText, StringComparison.OrdinalIgnoreCase) >= 0)
            return true;
    }
    return false;
}
```

The filter is case-insensitive and matches anywhere within the cell value.

---

### 4.7 Wake-on-LAN

**File:** `WOL.cs`

Wake-on-LAN sends a "magic packet" — a UDP broadcast containing the target's MAC address repeated 16 times — to UDP port 9.

```
Magic packet structure:
  6 × 0xFF  (sync stream)
  16 × MAC  (48-bit MAC address repeated)
  Total: 6 + (16 × 6) = 102 bytes
```

The user selects one or more rows in the grid (cell-selection mode — hold Shift or Ctrl to multi-select), then clicks "⚡ Wake-on-LAN".

```csharp
// MainWindow.xaml.cs
var selectedItems = StatusDataGrid.SelectedCells
    .Select(c => c.Item)
    .OfType<ScanStatus>()
    .Distinct()           // same row may appear multiple times (one per selected cell)
    .ToList();
```

**Requirement:** The MAC address must have been retrieved by a prior successful scan. WoL will not work if `MACAddress` is empty or `"N/A"`.

**Network requirement:** The target machine must be on the same broadcast domain (same subnet), or the router between them must forward directed broadcasts. WoL does not work across routed boundaries without special configuration.

---

### 4.8 Logger

**File:** `Logger.cs`

All significant events are written to a plain-text log file.

**Log path:**
```
%APPDATA%\IPProcessingTool\app.log
C:\Users\<username>\AppData\Roaming\IPProcessingTool\app.log
```

**Before v10.0.0:** The log was written to `Desktop\log.txt`. On managed machines with redirected desktops or restricted write access, log writes silently failed.

**Log format:**
```
2026-03-04 14:32:01 [INFO] User: RBC\artee, Context: InitializeFloorMappings, Additional Info: , Message: Loaded floor mappings from C:\...\floor_mappings.json
2026-03-04 14:32:15 [ERROR] User: RBC\artee, Context: ScanIPAsync, Additional Info: , Message: WMI connect failed for 10.9.115.99: Access denied
```

**Log levels:** `INFO`, `WARNING`, `ERROR`

The directory is created automatically on first write. If writing fails (permissions, disk full), the error is printed to console only — the app continues normally.

---

### 4.9 Input Window & Target Parsing

**File:** `ModernInputWindow.xaml.cs`

The placeholder text (grey hint shown when the box is empty) is implemented as a WPF TextBlock overlay, **not** as actual text in the TextBox:

```xml
<Grid>
    <TextBox Name="InputTextBox" .../>     <!-- always empty until user types -->
    <TextBlock IsHitTestVisible="False"    <!-- sits on top, invisible to mouse -->
               Foreground="#9CA3AF">
        <TextBlock.Style>
            <Style TargetType="TextBlock">
                <Setter Property="Visibility" Value="Collapsed"/>
                <Style.Triggers>
                    <!-- show ONLY when TextBox is truly empty -->
                    <DataTrigger Binding="{Binding Text, ElementName=InputTextBox}" Value="">
                        <Setter Property="Visibility" Value="Visible"/>
                    </DataTrigger>
                </Style.Triggers>
            </Style>
        </TextBlock.Style>
        Enter one or more targets...
    </TextBlock>
</Grid>
```

**Why not use GotFocus/LostFocus?** A previous approach stored the hint text inside the TextBox and compared strings on focus. It was fragile — any mismatch between the XAML text and the C# constant caused the hint to never disappear. The overlay approach keeps the TextBox truly empty, so parsing code never has to skip placeholder text.

**Parsing order** (`ParseSingleTarget`):

1. Contains `/` → CIDR expansion (`ExpandCIDR`)
2. Contains `-` and both sides are valid IPs → range expansion (`ExpandIPRange`)
3. Three octets, all valid bytes → segment expansion (`ExpandIPSegment` → .0 to .255)
4. Valid IP or hostname → used as-is

---

### 4.10 Progress Bar & Status Bar

**Progress bar** sits in its own row between the DataGrid and status bar. It has two columns:

```xml
<Grid Grid.Row="4" Margin="12,8,12,0">
    <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>    <!-- bar fills available width -->
        <ColumnDefinition Width="Auto"/> <!-- text to the right -->
    </Grid.ColumnDefinitions>
    <ProgressBar Name="ProgressBar" Grid.Column="0"/>
    <TextBlock   Name="ProgressText" Grid.Column="1" Margin="8,0,0,0"/>
</Grid>
```

`UpdateProgressBar(int value, int done, int total)` is called from every worker task:

```csharp
// value = 0–100 (percentage), done = count completed, total = count total
ProgressBar.Value  = value;
ProgressText.Text  = done > 0 ? $"{done} / {total} ({value}%)" : "";
```

When scanning stops (user cancels or scan completes), `UpdateProgressBar(0)` resets both the fill and the text.

**Status bar** (bottom strip) shows plain text only — no buttons:

- `"Ready"` — on startup
- `"Scanning…"` — during scan
- `"Scanning stopped by user."` — after Stop
- `"Done — 142 Online | 28 Offline | 5 Errors | 25 Unreachable"` — after completion
- `"Grid cleared."` — after Clear

**Conditional buttons:**

| Button | Visible when |
|--------|-------------|
| Stop   | `DisableButtons()` is called (scan starts) |
| Stop   | Hidden again by `EnableButtons()` (scan ends/stops) |
| Clear  | `EnableButtons()` is called AND grid has data |
| Clear  | Hidden again after `ClearButton_Click()` empties the grid |

---

## 5. Key Classes & Files

### `ScanStatus` (in `MainWindow.xaml.cs`)

The data model for one scanned host. Every property corresponds to one DataGrid column.

| Property | Source | Notes |
|----------|--------|-------|
| `IPAddress` | Input | Original IP or resolved hostname |
| `Status` | Ping | Online / Offline / Unreachable / Timeout / Error / Scanning... |
| `Hostname` | DNS reverse lookup | |
| `Floor` | `GetFloorForIP()` | In-memory dictionary lookup |
| `MachineModel` | WMI `Win32_ComputerSystem.Model` | e.g. "HP EliteBook 840 G9" |
| `WindowsVersion` | Remote registry `DisplayVersion` | e.g. "23H2" |
| `LastLoggedUser` | Remote registry `LogonUI\LastLoggedOnUser` | |
| `BIOSVersion` | WMI `Win32_BIOS.SMBIOSBIOSVersion` | |
| `SMBIOSVersion` | WMI `Win32_BIOS.SMBIOSMajor/MinorVersion` | |
| `EmbeddedControllerVersion` | WMI `Win32_BIOS.EmbeddedController...` | "N/A (Virtual)" on VMs |
| `MACAddress` | WMI `Win32_NetworkAdapter` | Preferred from Ethernet adapter |
| `NIC0LAN` | WMI | First Ethernet adapter — full info string |
| `NIC1WiFi` | WMI | First Wi-Fi adapter — full info string |
| `NIC2LAN2` | WMI | Second Ethernet adapter |
| `NIC3` | WMI | Any fourth adapter |
| `RAMSize` | WMI `Win32_PhysicalMemory` | |
| `OfficeVersion` | Remote registry (64-bit + WOW6432Node) | |
| `DiskSize` | WMI `Win32_LogicalDisk` | |
| `FreeSpace` | WMI `Win32_LogicalDisk` | |
| `OpenPorts` | TCP connect attempts | Comma-separated list |
| `PingTime` | ICMP ping | Milliseconds |

### `AppSettings` (`AppSettings.cs`)

Serializable settings model. `Load()` and `Save()` are static/instance methods.
`ColumnSettingData` is a simple DTO (no WPF dependencies) used for JSON serialisation.

### `ColumnSetting` (in `MainWindow.xaml.cs`)

UI model for one column toggle. Used by Settings dialog's `ItemsControl` with checkboxes.

### `WOL` (`WOL.cs`)

One static async method: `WakeOnLan(string macAddress)`.
Parses any MAC format (colon, dash, or none), builds the 102-byte magic packet, broadcasts on UDP/9.

### `Logger` (`Logger.cs`)

Static class. Thread-safe (uses `File.AppendAllText` which is atomic per call on Windows for small writes).
Includes Windows username in every entry via `WindowsIdentity.GetCurrent().Name`.

---

## 6. WMI Queries Reference

All WMI queries run over the network using `\\IP\root\cimv2` as the scope.
They require the scanning user to have remote WMI access on the target (typically Domain Admins or a delegated group).

| Query | Data Retrieved | Notes |
|-------|---------------|-------|
| `Win32_ComputerSystem` | Manufacturer, Model, UserName | UserName = currently logged in (interactive only) |
| `Win32_BIOS` | SMBIOSBIOSVersion, ReleaseDate, SMBIOSMajor/MinorVersion, EmbeddedController versions | Single query for all BIOS data |
| `Win32_NetworkAdapterConfiguration WHERE IPEnabled=True` | IPAddress, MACAddress | Used to build IP lookup dict |
| `Win32_NetworkAdapter WHERE PhysicalAdapter=True AND Manufacturer != 'Microsoft'` | Name, AdapterTypeId, MACAddress, Speed, NetConnectionStatus | Used to classify and display NICs |
| `Win32_PhysicalMemory` | Capacity | Summed for total RAM |
| `Win32_LogicalDisk WHERE DriveType=3` | Size, FreeSpace | DriveType=3 = local fixed disk |
| `Win32_OperatingSystem` | Caption | e.g. "Windows 11 Pro" — backup if registry fails |

**Registry reads** (via `RegistryKey.OpenRemoteBaseKey`):

| Hive | Path | Value | Purpose |
|------|------|-------|---------|
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `DisplayVersion` | Windows version e.g. "23H2" |
| HKLM | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `ReleaseId` | Fallback (frozen at "2009" on 23H2+) |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` | `LastLoggedOnUser` | Last user to log in |
| HKLM | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` | `DisplayName` | Office version (64-bit install) |
| HKLM | `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*` | `DisplayName` | Office version (32-bit install on 64-bit OS) |

---

## 7. Changelog — Every Commit Explained

### Branch: `feat/v10.0.0`

---

#### `c7e3903` — fix: reset progress bar to zero when scan is stopped

**What changed:** `StopButton_Click` now calls `UpdateProgressBar(0)` before `EnableButtons()`.

**Why:** When a scan was cancelled mid-way, the progress bar stayed at whatever percentage it reached. Users had no visual feedback that the scan had truly stopped.

**File:** `MainWindow.xaml.cs`

---

#### `11a6a93` — fix: replace placeholder text hack with WPF overlay TextBlock

**What changed:** `ModernInputWindow` input box placeholder completely rewritten.

**Before:** Placeholder text was stored directly in `TextBox.Text`. `GotFocus` cleared it if text matched a constant; `LostFocus` restored it. The XAML text and the C# constant had different wording → comparison always failed → hint never disappeared.

**After:** TextBox is always empty. A `TextBlock` overlay (transparent to mouse) is shown via a `DataTrigger` only when `TextBox.Text == ""`. Disappeared the moment any character is typed — no string comparison needed.

**Files:** `ModernInputWindow.xaml`, `ModernInputWindow.xaml.cs`

---

#### `37f7c42` — feat(ui): fix progress text, conditional buttons, cell selection

**What changed:** Three UI improvements in one commit:

1. **Progress text position** — text moved from on top of the bar (overlap) to a separate column to the right.
2. **Stop button** — hidden (`Collapsed`) by default; shown only while a scan is running; hidden again on completion or cancellation.
3. **Clear button** — hidden by default; shown after a scan finishes with data in the grid; hidden again after clearing.
4. **Wake-on-LAN cell compatibility** — switched from `SelectedItems` (row-selection API) to `SelectedCells.Select(c => c.Item).Distinct()` to work with the new cell-selection mode.

**Files:** `MainWindow.xaml`, `MainWindow.xaml.cs`

---

#### `2ce6aaa` — feat: fix NIC scanning + add sort & filter to results grid

**What changed:**

1. **NIC detection rewrite** — see §4.4 for full detail. Old approach used `AdapterType` string; new approach uses `AdapterTypeId` integer + name keyword fallback.
2. **Sort** — `CanUserSortColumns="True"` + `SortMemberPath` on each column. Click column header to sort.
3. **Filter** — `ICollectionView` + `SearchBox` with live predicate. Matches any visible column, case-insensitive.
4. **Cell selection** — `SelectionUnit="Cell"` on DataGrid. Click to select one cell; hold Shift to extend; hold Ctrl to multi-select. Custom cell template shows blue highlight (#BFDBFE) on selected cells. Row hover remains (#EFF6FF) but no full-row selection colour.
5. **NIC3 slot added** — fourth NIC slot for Wireless WAN or secondary adapters.
6. **Search bar row added** to `MainWindow.xaml` (Grid row 2 of 6).

**Files:** `MainWindow.xaml`, `MainWindow.xaml.cs`

---

#### `a2533dd` — feat(ui): modern redesign — consistent design system across all windows

**What changed:** Complete visual redesign of all three windows.

**Design system introduced:**

| Token | Value | Usage |
|-------|-------|-------|
| Navy | `#002D62` | Header bar background |
| Primary blue | `#0057B8` | Start Scan button |
| Success green | `#16A34A` | Save button |
| Amber | `#B45309` | Wake-on-LAN button |
| Danger red | `#DC2626` | Stop button |
| Surface | `#F1F5F9` | Window background |
| Border | `#E2E8F0` | Card borders, dividers |
| Dark header | `#1E3A5F` | DataGrid column headers |

**All buttons** share a single `RbcButtonTemplate` with rounded corners (CornerRadius=6), hover opacity (0.83), pressed opacity (0.68), and disabled opacity (0.38).

**DataGrid:** alternating row colours (white / `#F8FAFC`), dark header row, row hover highlight.

**Files:** `MainWindow.xaml`, `ModernInputWindow.xaml`, `Settings.xaml`

---

#### `ada35c3` — feat: v10.0.0 — bug fixes, 23H2 compat, perf & UX improvements

**What changed:** Large foundational commit — see `IMPROVEMENTS.md` for full before/after detail. Summary:

| Area | Fix |
|------|-----|
| `GetWindowsReleaseIdAsync` | Removed broken WMI loop; direct registry read; prefers `DisplayVersion` over `ReleaseId` |
| `GetLastLoggedUserAsync` | Fixed to read `LogonUI\LastLoggedOnUser` from registry instead of WMI current session |
| `GetMachineModelAsync` | Changed from `Win32_ComputerSystemProduct.Version` (blank) to `Win32_ComputerSystem.Model` |
| `GetBIOSInfoAsync` | 3 separate WMI queries merged into 1 |
| EC version 255.255 | Displayed as "N/A (Virtual)" on Hyper-V/VMware |
| `Items.Refresh()` | Removed — caused UI freeze on every row update |
| Hostname resolution | Parallelised with `Task.WhenAll` |
| `GetOfficeVersionAsync` | Checks WOW6432Node fallback for 32-bit Office on 64-bit OS |
| Settings persistence | `AppSettings.cs` created; JSON round-trip to `%APPDATA%` |
| Floor mappings | Externalised to `floor_mappings.json`; built-in fallback |
| Logger path | Changed from Desktop to `%APPDATA%\IPProcessingTool\app.log` |
| Column bindings | `PropertyName` + `nameof()` replacing fragile string.Replace |
| Dead code | `_batch`, `BATCH_SIZE`, `IsValidIPSegment`, `HighlightInvalidInput`, `ShowInvalidInputMessage`, `ShowSuccessMessage()` all removed |
| Progress bar | Percentage text added (`47 / 200 (23%)`) |
| Scan summary | Status bar shows online/offline/error counts on completion |

**Files:** `MainWindow.xaml.cs`, `Settings.xaml.cs`, `AppSettings.cs` (new), `Logger.cs`

---

### Older commits (pre-v10.0.0, on `UI_Scan` / `main`)

These are the original development history. Listed briefly for context.

| Commit | Summary |
|--------|---------|
| `42a208c`–`dfcfdb1` | Added new UI for scanning (ModernInputWindow iterations) |
| `88f156f` | Added hostname scan feature |
| `2e14e9c` | Bulk IP input functionality |
| `64fdeb5`, `5495832` | Floor mappings introduced (hardcoded) |
| `a4eb944` | Port scanning added |
| `c684b02` | MAC address query updated |
| `16f0315` | Machine model query updated |
| `aab9d5f` | NIC information added |
| `32ab672` | BIOS date fix |
| `2628c9a` | BIOS version/data added |
| `2c1101b` | Windows version query updated |
| `1a10984` | Wake-on-LAN added |
| `1556c65` | Rescan button added |
| `814a371` | MAC address added |
| `3defe78` | Ping time added |
| `79fc200` | Initial commit |

---

## 8. Common Pitfalls & Why We Fixed Them

### "Windows Version shows Unknown"

**Cause:** `ReleaseId` registry key is frozen at `"2009"` on Windows 11 22H2+ as a legacy artefact. The old code relied on it.
**Fix:** Always prefer `DisplayVersion` (returns `"23H2"`, `"24H2"`, etc.).

### "Machine Model is blank or shows 'System Version'"

**Cause:** `Win32_ComputerSystemProduct.Version` is not populated by most OEM BIOSes.
**Fix:** Use `Win32_ComputerSystem.Model` (always populated with the real model name).

### "Last Logged User is empty when nobody is logged in"

**Cause:** `Win32_ComputerSystem.UserName` only returns a value if someone is actively logged in interactively.
**Fix:** Read the `LastLoggedOnUser` registry value which persists even after logoff.

### "Grid freezes during large scans"

**Cause:** `StatusDataGrid.Items.Refresh()` was called on every single row update. With 256 IPs, this meant 256 full UI redraws.
**Fix:** Removed the call. `ObservableCollection` raises `CollectionChanged` automatically; WPF handles the rest.

### "Placeholder text stays in input box"

**Cause:** Placeholder text was stored inside the TextBox. The C# constant and the XAML `Text=` property had different wording, so the equality check always failed.
**Fix:** TextBox is always empty; placeholder is a separate non-interactive TextBlock overlay.

### "Settings reset on every launch"

**Cause:** No persistence mechanism existed. All settings were initialised to defaults in the constructor.
**Fix:** `AppSettings.cs` reads/writes `%APPDATA%\IPProcessingTool\settings.json` on every open/save of the Settings dialog.

### "WoL button doesn't work after switching to cell-selection mode"

**Cause:** `StatusDataGrid.SelectedItems` is the row-selection API. With `SelectionUnit="Cell"`, it's always empty.
**Fix:** Use `StatusDataGrid.SelectedCells.Select(c => c.Item).OfType<ScanStatus>().Distinct()`.

---

## 9. How to Extend the Tool

### Add a new data column

1. Add a property to `ScanStatus`:
   ```csharp
   public string BitLockerStatus { get; set; } = "N/A";
   ```

2. Add a `ColumnSetting` entry in `InitializeColumnSettings()`:
   ```csharp
   new ColumnSetting { Name = "BitLocker", PropertyName = nameof(ScanStatus.BitLockerStatus), IsSelected = false }
   ```

3. Populate it in `ScanIPAsync()`:
   ```csharp
   scanStatus.BitLockerStatus = await GetBitLockerStatusAsync(scope, ct);
   ```

4. Write `GetBitLockerStatusAsync()` using WMI or registry as needed.

The column will appear in Settings → Data Columns and can be toggled on/off.

### Add a new floor mapping

See §4.2. Either edit `floor_mappings.json` or add to `DefaultFloorMappings`.

### Change the settings file format

Add new properties to `AppSettings`. Old JSON files without those keys will deserialise with default values — no migration needed.

### Change the log location

Edit the `logFilePath` in `Logger.cs`. The directory is created automatically.

### Add a new scan target format

Edit `ParseSingleTarget()` in `ModernInputWindow.xaml.cs`. Add your detection logic before the final `IsValidIPOrHostname` fallback.
