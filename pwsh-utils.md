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


_Description:_ Retrieves a list of installed programs and exports it to a CSV file called "InstalledPrograms.csv".

---

### **8. Monitor a file for changes in real time**

```powershell
$Datei = 'C:\Path\to\your\File.txt'
Get-Content $Datei -Wait
```

_Description:_ Displays the contents of a file and updates in real time as soon as changes are made.

---

### **9. Back up a directory and exclude certain file types**

```powershell
robocopy "C:\Quelle" "D:\Backup" /E /XD *.tmp *.log
```

_Description:_ Copies all files and subdirectories from `C:\Source` to `D:\Backup`, but excludes files with the extensions `.tmp` and `.log`.

---

### **10. Check whether a port is open on a remote computer**

```powershell
Test-NetConnection -ComputerName RemoteHostName -Port 80
```

_Description:_ Tests the connectivity to a remote host on a specific port (e.g. port 80).

---

## To view running PowerShell processes, you can use the `Get-Process` cmdlet to get a list of all active processes. You can filter specifically for PowerShell processes by searching for the process name "powershell" or "pwsh" (for PowerShell Core). Here are some ways you can do this

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
