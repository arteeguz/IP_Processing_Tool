# Deployment Guide — IP Processing Tool

## Recommended approach: network share

Running the app directly off a network share (e.g. `\\netapp2b\DSS Interns\Scanner`) is
the right call for an internal tool like this. It means:

- One place to update — overwrite the files and every user gets the new version on next launch.
- No installation needed on any machine.
- Works fine from a domain share; Windows does not block UNC-path executables the same way
  it blocks files downloaded from the internet.

---

## Step 1 — Publish the app

Open a terminal in the repo root and run:

```powershell
dotnet publish IP_Processing_Tool/IP_Processing_Tool.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  --output ./publish `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true
```

**Why `--self-contained true` with `PublishSingleFile`?**

This bundles the .NET 8 runtime into the exe. Without it, every user's machine needs
the .NET 8 Desktop Runtime installed separately. Self-contained removes that dependency
entirely — the exe just works. The trade-off is a larger file (~160 MB vs ~2 MB), but
for a tool that is run occasionally that is a non-issue.

If you know .NET 8 Desktop Runtime is already deployed to all machines (e.g. via SCCM or
an existing company-wide install), you can drop `--self-contained true` and the exe
will be ~2 MB:

```powershell
dotnet publish IP_Processing_Tool/IP_Processing_Tool.csproj `
  --configuration Release `
  --runtime win-x64 `
  --no-self-contained `
  --output ./publish
```

---

## Step 2 — Copy to the share

After publish, the `./publish` folder will contain:

```
IP_Processing_Tool.exe      ← the app (single file if self-contained)
```

Copy the contents of `./publish` to your share, for example:

```
\\netapp2b\DSS Interns\Scanner\
```

If a `floor_mappings.json` already exists on the share (from a previous deployment),
**do not overwrite it** — it contains any custom floor/subnet mappings that have been
saved from Settings. The exe itself is the only file that changes between versions.

---

## Step 3 — Share permissions

| Who | Required permission |
|-----|---------------------|
| Regular users (running the tool) | Read + Execute |
| Admin / tool maintainer | Read + Write + Execute |

Users only need Read + Execute to launch and run scans. The app stores all per-user state
(settings, logs) in `%APPDATA%\IPProcessingTool\` on the user's own machine, so users
do not need write access to the share for normal operation.

**Exception — floor_mappings.json:**
The Floor Mappings editor in Settings writes `floor_mappings.json` next to the exe on the
share. If you want users to be able to save floor mapping changes from the UI, they need
Write access to the share folder.

Two sensible approaches:

- **Centrally managed (recommended):** Give only admins Write access. One person manages
  `floor_mappings.json` (either via the Settings UI while running from a writable copy, or
  by editing the JSON directly). All users read from it.

- **Shared write access:** Grant all users Modify on the share folder. Simpler, but users
  could accidentally overwrite each other's changes if they both hit Save at the same time
  (rare in practice for a small team).

---

## Step 4 — First run / verification

1. Log in as a regular user (not the admin who copied the files).
2. Navigate to `\\netapp2b\DSS Interns\Scanner\` in File Explorer.
3. Double-click `IP_Processing_Tool.exe`.
4. The app should launch directly — no install prompt, no UAC prompt.
5. Run a quick scan against one known IP to confirm WMI connectivity works.

**If Windows shows a security warning ("Do you want to run this file?"):**
This is the standard "file from a network location" prompt. Click **Run**. It will only
appear once per user per file version. It is not a sign that anything is wrong.

If the prompt appears every time (unusual on a domain share), an admin can unblock
the file for everyone by right-clicking the exe → Properties → Unblock, or via GPO
(`Computer Configuration → Windows Settings → Security Settings → Local Policies →
Security Options → "Network access: Let Everyone permissions apply to anonymous users"`
is unrelated — the relevant policy is under `User Configuration → Windows Settings →
Security Settings → Software Restriction Policies` or SmartScreen settings).

---

## Updating to a new version

1. Build and publish using the same command in Step 1.
2. Copy the new `IP_Processing_Tool.exe` to the share, overwriting the old one.
3. Do **not** delete `floor_mappings.json` if it exists — it preserves custom mappings.
4. Users who relaunch the app get the new version immediately. No action needed on their end.

---

## File locations summary

| File | Location | Notes |
|------|----------|-------|
| `IP_Processing_Tool.exe` | `\\server\share\` | The app itself — the only file you deploy |
| `floor_mappings.json` | `\\server\share\` | Created on first Save from Settings; shared by all users |
| `settings.json` | `%APPDATA%\IPProcessingTool\` | Per-user settings (columns, timeouts, etc.) |
| `app.log` | `%APPDATA%\IPProcessingTool\` | Per-user log file |

---

## Running the scanner without admin credentials

### Why admin is needed

The app does **not** require local admin on the machine it runs on — no UAC prompt,
no elevation needed to launch. The credential requirement is on the **target machines
being scanned**: WMI remote access and remote registry both require the scanning account
to be a local administrator on each target. That is a Windows default, not a limitation
of this app.

Specifically, every scan does:
- `ManagementScope` connection to `\\{ip}\root\cimv2` (WMI)
- `RegistryKey.OpenRemoteBaseKey` to read Windows version, last-logged user, Office version

Both use the credentials of whoever is running the exe — no credentials are stored in
the app.

### Option A — GPO delegation (best long-term solution, no code change)

IT can grant a security group the minimum permissions needed to run the scanner, without
making those users full Domain Admins. Steps for IT:

**1. Create an AD group** (e.g. `GRP-Scanner-Operators`) and add the scanner users to it.

**2. Grant WMI remote access** on target machines (deploy via GPO):

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → System Services
        → Windows Management Instrumentation → set to Automatic
```

Then on the WMI namespace itself — run this once on a target machine to test, then
deploy via GPO startup script across the estate:

```powershell
# Run on each target machine (or via GPO startup script)
$group = "DOMAIN\GRP-Scanner-Operators"
$ns    = "root/cimv2"

$security = Get-WmiObject -Namespace $ns -Class __SystemSecurity
$sd = $security.GetSD()

# Required access mask: Execute Methods (1) + Enable Account (2) +
#                       Remote Enable (128) + Read Security (131072)
$accessMask = 1 -bor 2 -bor 128 -bor 131072

# Use wmimgmt.msc for a GUI approach instead:
#   Start → wmimgmt.msc → right-click WMI Control → Properties
#   → Security tab → root\cimv2 → Security → Add group → tick
#   "Execute Methods", "Enable Account", "Remote Enable", "Read Security"
```

The GUI approach via `wmimgmt.msc` is simpler for a one-off test; the PowerShell
approach is what you bake into a GPO startup script.

**3. Grant Remote Registry read access** on target machines:

```
Computer Configuration
  → Preferences
    → Windows Settings
      → Registry
        → New Registry Item
          Key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
          Permissions: add GRP-Scanner-Operators → Read
          (repeat for LogonUI and Uninstall keys)
```

Or, simpler, enable and start the RemoteRegistry service via GPO and grant the group
read-only access to `HKLM` remotely:

```powershell
# On a target machine — grants group read-only remote registry access
$acl = Get-Acl "HKLM:\"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "DOMAIN\GRP-Scanner-Operators", "ReadKey", "ContainerInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl -Path "HKLM:\" -AclObject $acl
```

**4. Allow WMI through Windows Firewall** (usually already done on managed machines):

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Windows Firewall with Advanced Security
        → Inbound Rules → enable "Windows Management Instrumentation (WMI-In)"
```

Once this GPO is applied across the estate, any member of `GRP-Scanner-Operators` can
run the tool successfully without being a Domain Admin or local admin on targets.

---

### Option B — `runas` wrapper script (no IT involvement, no code change)

If GPO delegation is not feasible, create a batch file on the share next to the exe:

**`Run Scanner (Admin).bat`**
```bat
@echo off
runas /user:DOMAIN\scan-service-account "\\netapp2b\DSS Interns\Scanner\IP_Processing_Tool.exe"
```

Users double-click the batch file instead of the exe. Windows prompts for the
`scan-service-account` password, then launches the scanner under those credentials.

Downsides:
- Users see a cmd window flash while the app launches.
- The service account password must be shared verbally or in a secure note — anyone
  who knows it can use it for other things.
- If the password changes, you update it nowhere (users just re-enter it at the prompt).

This is a pragmatic workaround for a small team where GPO changes are slow to get approved.

---

### Option C — credential prompt in the app (possible future improvement)

The `ConnectionOptions` object the app passes to WMI already supports `Username` and
`Password` fields. If added, the app could show a one-time credential dialog at startup
(or in Settings) and use a scan service account's credentials for all WMI connections.

The remote registry calls (`RegistryKey.OpenRemoteBaseKey`) do **not** support explicit
credentials — they always use the current user's token. Those would need to be rewritten
to use the WMI `StdRegProv` class (which does respect `ConnectionOptions` credentials)
or wrapped in `WindowsIdentity.RunImpersonated` after a `LogonUser` P/Invoke call.

This is the most user-friendly option but requires a meaningful code change. Raise it as
a feature request if Option A or B does not work for your environment.

---

### Summary

| Option | IT involvement | Code change | Best for |
|--------|---------------|-------------|----------|
| A — GPO delegation | Yes (one-time) | None | Permanent deployment to many users |
| B — `runas` batch | None | None | Quick workaround, small team |
| C — credential prompt in app | None | Medium | If A and B are both blocked |

---

## Alternative: ClickOnce (only worth it if auto-update UX matters)

ClickOnce installs the app locally on each user's machine and auto-updates from the share
when a new version is published. Benefits over the direct-run approach:

- Launch is faster (runs locally, not from the network on every click).
- Update check happens silently in the background.

Downsides for this use case:

- More complex publish (`dotnet publish` does not support ClickOnce directly; you need
  Visual Studio's Publish wizard or the `Mage.exe` tool).
- Requires the .NET 8 Desktop Runtime on each machine (ClickOnce cannot bundle it).
- First-time install requires users to open a `.application` file and confirm an install
  prompt, which some IT policies block.

For a small internal team where the direct-run approach already works, ClickOnce adds
complexity without meaningful benefit. Stick with the direct-run approach.
