# Powershell Utils

## **Attention Notes**

- **Be careful when executing commands that delete or modify files (e.g. delete empty directories).**

- Adjust paths such as `'C:\'` or `'C:\Path\to\your\file.txt'` according to your system environment.

- The parameter `-ErrorAction SilentlyContinue` suppresses error messages and continues execution.

- Use `-Force` to include hidden and system files.

## Copy and edit this variable, its used in the commands as parameter

```powershell
Set-Variable -Name "SEARCH_STR" -Value "YourSearchString"
```

### **1. Find all files on all available drives that have a specific string in their name**

```powershell
Get-PSDrive -PSProvider 'FileSystem' | ForEach-Object {
    Get-ChildItem -Path "$($_.Root)\*" -Recurse -ErrorAction SilentlyContinue -Force |
    Where-Object { $_.Name -like "*$SEARCH_STR*" } |
    Select-Object FullName
}
```

_description:_ This command searches all file system drives for files whose names contain the specified string. Errors are suppressed so that the search continues even if there are problems.

---

### **2. find all files that have a specific string in their content**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -File -ErrorAction SilentlyContinue -Force |
Select-String -Pattern "$SEARCH_STR" -ErrorAction SilentlyContinue |
Select-Object Path
```

_description:_ This command searches all files under `C:\` for those that contain the specified string in their content. Errors are handled silently to continue processing.

---

### **3. Alle Verzeichnisse rekursiv finden, die einen bestimmten String im Namen haben**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -Directory -ErrorAction SilentlyContinue -Force |
Where-Object { $_.Name -like "*$SEARCH_STR*" } |
Select-Object FullName
```

_description:_ This command searches all directories under `C:\` recursively for those whose names contain the specified string. Errors are suppressed so as not to interrupt the search.

---

**Additional useful commands:**

---

### **4. Find and delete all empty directories**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -Directory -ErrorAction SilentlyContinue -Force |
Where-Object { @(Get-ChildItem $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0 } |
Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
```

_description:_ This command finds all empty directories under `C:\` and deletes them. Errors are handled silently.

---

### **5. List running processes sorted by memory consumption**

```powershell
Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 10
```

_Description:_ Displays the top 10 processes that consume the most memory.

---

### **6. Find all large files over a certain size (e.g. over 100MB)**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -File -ErrorAction SilentlyContinue -Force |
Where-Object { $_.Length -gt 100MB } |
Select-Object FullName, @{Name="SizeMB";Expression={$_.Length / 1MB -as [int]}}
```

_Description:_ Searches for files over 100MB under `C:\` and lists their paths and sizes in MB.

---

### **7. Export list of installed programs**

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Export-Csv -Path "InstallierteProgramme.csv" -NoTypeInformation
```

_Description:_ Retrieves a list of installed programs and exports it to a CSV file called "InstalledPrograms.csv".


### **8. Retrieve all Autostart Files from the Registry**

```powershell
# usefull whenever you want to check which 
# files are autostart when you starting your windows machine
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        Write-Host "`nEntries in $path`n" -ForegroundColor Green
        Get-ItemProperty -Path $path | Select-Object *
    }
}
```


---

### **9. Monitor a file for changes in real time**

```powershell
Set-Variable -Name "File" -Value "C:\Your\File.txt"
Get-Content $File -Wait
```

_Description:_ Displays the contents of a file and updates in real time as soon as changes are made.

---

### **10. Back up a directory and exclude certain file types**

```powershell
robocopy "C:\Source" "D:\Backup" /E /XD *.tmp *.log
```

_Description:_ Copies all files and subdirectories from `C:\Source` to `D:\Backup`, but excludes files with the extensions `.tmp` and `.log`.

---

### **10. Check whether a port is open on a remote computer**

```powershell
Test-NetConnection -ComputerName RemoteHostName -Port 80
```

_Description:_ Tests the connectivity to a remote host on a specific port (e.g. port 80).

### **11. Find hidden Registry Entries**

```powershell
# Function to detect registry keys with non-printable characters in their names
function Get-NonPrintableRegistryKeys {
    param (
        [string]$KeyPath
    )

    try {
        $subKeys = Get-ChildItem -Path $KeyPath -ErrorAction Stop

        foreach ($subKey in $subKeys) {
            # Check if the key name contains non-printable characters
            if ($subKey.PSChildName -match '[^\x20-\x7E]') {
                Write-Output "Key with non-printable characters: $($subKey.PSPath)"
            }
            # Recursively call the function for each subkey
            Get-NonPrintableRegistryKeys -KeyPath $subKey.PSPath
        }
    }
    catch {
        # Handle exceptions if necessary
    }
}

# Start scanning from the root hives
$rootHives = @("HKLM:\", "HKU:\")

foreach ($hive in $rootHives) {
    Get-NonPrintableRegistryKeys -KeyPath $hive
}
```

_Description:_ If you worry your system could be infected, one trace malware can leave are hidden registry entries, this pwsh script tries to find those

---

### To view running PowerShell processes, you can use the `Get-Process` cmdlet to get a list of all active processes. You can filter specifically for PowerShell processes by searching for the process name "powershell" or "pwsh" (for PowerShell Core). Here are some ways you can do this

1. **Show all processes**:

   ```powershell
   Get-Process
   ```

2. **Show only PowerShell processes**:

   ```powershell
   Get-Process -Name powershell
   ```

   For PowerShell Core:

   ```powershell
   Get-Process -Name pwsh
   ```

3. **Show detailed information on PowerShell processes**:

   ```powershell
   Get-Process -Name powershell | Format-List *
   ```

   For PowerShell Core:

   ```powershell
   Get-Process -Name pwsh | Format-List *
   ```

4. **Terminating a specific PowerShell process**:
   You can terminate a specific PowerShell process using its process ID (PID). For example:

   ```powershell
   Stop-Process -Id <Prozess-ID>
   ```

   To find the process ID, you can use `Get-Process`:

   ```powershell
   Get-Process -Name powershell
   ```

   Then select the PID from the list and use `Stop-Process` to end the process.

```powershell
# Show all running PowerShell processes
Get-Process -Name powershell

# Show detailed information about a specific PowerShell process (for example, the first one in the list)
Get-Process -Name powershell | Select-Object -First 1 | Format-List *
```

### Kills all processes found under the searched Name

```powershell
Get-Process -Name $SEARCH_STR | ForEach-Object {
    # List the process name and PID
    Write-Host "Found process: Name = $($_.ProcessName), PID = $($_.Id)"

    # Stop the process
    Stop-Process -Id $_.Id -Force

    # Confirm the process has been stopped
    Write-Host "Stopped process with PID $($_.Id)"
}
```

### Open Your Favorit Websites all at once

```powershell
$urls = @("https://www.example1.com", "https://www.example2.com")
foreach ($url in $urls) {
    Start-Process "chrome.exe" $url
}
```

### Extract zip Archieve 

```powershell
Expand-Archive -Path "C:\Archive\Files.zip" -DestinationPath "C:\Extracted"
```

### Compress Files into ZIP 

```powershell
Compress-Archive -Path "C:\Files\*" -DestinationPath "C:\Archive\Files.zip"
```

### Batch Rename File matching Pattern 

```powershell
Get-ChildItem *.txt | Rename-Item -NewName {$_.Name -Replace 'old','new'}
```

### Compute a File Hash 

```powershell
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA256
```

### Automate and Schedule Tasks

```powershell
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File 'C:\Scripts\YourScript.ps1'"
$Trigger = New-ScheduledTaskTrigger -Daily -At 9AM
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "DailyScriptRun" -Description "Runs a script daily at 9 AM"
```

### Check Recursively File hashes on VT

```powershell
$ApiKey = "YOUR_VIRUSTOTAL_API_KEY"
$Files = Get-ChildItem -Path "C:\Path\To\Scan" -Recurse -File
foreach ($File in $Files) {
    $Hash = (Get-FileHash -Algorithm SHA256 -Path $File.FullName).Hash
    $Response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Headers @{ "x-apikey" = $ApiKey }
    Write-Output "$($File.FullName): $($Response.data.attributes.last_analysis_stats)"
}
```

### Display open Network Connections

```powershell
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

### Enable / Disable Windows Service

```powershell
# To disable a service
Set-Service -Name "ServiceName" -StartupType Disabled

# To enable a service
Set-Service -Name "ServiceName" -StartupType Automatic
```

### Backup The Registry 

```powershell
reg export HKLM\Software "C:\Backup\SoftwareRegistryBackup.reg" /y
```

### Display Env Variables

```powershell
Get-ChildItem Env:
```

### Hide Folders or Files

```powershell
attrib +h "C:\Path\To\FileOrFolder"
```



