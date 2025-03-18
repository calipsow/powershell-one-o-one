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

### **Find all files that have a specific string in their content**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -File -ErrorAction SilentlyContinue -Force |
Select-String -Pattern "$SEARCH_STR" -ErrorAction SilentlyContinue |
Select-Object Path
```

_description:_ This command searches all files under `C:\` for those that contain the specified string in their content. Errors are handled silently to continue processing.

---

### **3. Recursively find all directories that have a specific string in their name**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -Directory -ErrorAction SilentlyContinue
-Force | Where-Object { $_.Name -like "*$SEARCH_STR*" } |
Select-Object FullName
```

_description:_ This command searches all directories under `C:\` recursively for those whose names contain the specified string. Errors are suppressed so as not to interrupt the search.

---

**Additional useful commands:**

---

### **4. Find and delete all empty directories**

```powershell
Get-ChildItem -Path 'C:\' -Recurse -Directory -ErrorAction SilentlyContinue -Force |
Where-Object { 
 @(Get-ChildItem $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0 
} | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
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


### Advanced Scripts

**1. Continuously Stop a Certain Process When It Starts Up**

This script monitors for a specific process and stops it whenever it starts. This can be useful for preventing unwanted applications from running.

```powershell
$processName = "notepad"
while ($true) {
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "$processName is running. Stopping it..."
        Stop-Process -Name $processName -Force
    }
    Start-Sleep -Seconds 5
}
```

*Explanation:*

- **`$processName`**: Set this to the name of the process you want to stop (e.g., `"notepad"`).
- The script enters an infinite loop (`while ($true)`), continuously checking if the process is running.
- **`Get-Process`**: Retrieves the process if it's running.
- **`Stop-Process`**: Terminates the process if found.
- **`Start-Sleep -Seconds 5`**: Waits for 5 seconds before checking again, to reduce CPU usage.

**Note:** Use this script responsibly. Continuously stopping a process can affect system stability or user experience. Ensure that you're not violating any company policies or interfering with critical system processes.

---

**2. Script to Update Installed Software to the Latest Versions**

This script retrieves a list of installed software, checks for available updates, and installs updates if newer versions are found.

### Option 1: Using Winget (Windows Package Manager)

**Prerequisites:**

- **Winget Installed**: Ensure that Winget is installed on your system. Winget comes pre-installed on Windows 10 version 1809 and later. If not installed, you can get it from the [Microsoft Store](https://www.microsoft.com/p/app-installer/9nblggh4nns1) or [GitHub Releases](https://github.com/microsoft/winget-cli/releases).

**Script:**

```powershell
# Ensure Winget is installed
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
 Write-Error "Install Winget: https://github.com/microsoft/winget-cli/releases"
 exit
}

# Get list of upgradable packages via Winget
$updates = winget upgrade --accept-source-agreements 
--accept-package-agreements | 
Select-Object -Skip 2 | 
ConvertFrom-Csv -Header "Name","Id","Version","Available","Source"

foreach ($package in $updates) {
 Write-Host "Updating $($package.Name) to Version $($package.Available)"
 winget upgrade --id $package.Id --accept-source-agreements 
 --accept-package-agreements --silent
}
```

*Explanation:*

- **`winget upgrade`**: Lists packages with available updates.
- **`ConvertFrom-Csv`**: Parses the output into objects for easy handling.
- The script iterates through each upgradable package and performs the upgrade silently.
- **Flags Used:**
  - `--accept-source-agreements` and `--accept-package-agreements`: Automatically accept agreements.
  - `--silent`: Perform silent installation (if supported by the installer).

**Notes:**

- **Administrator Privileges**: Some packages may require elevated permissions. Run PowerShell as an administrator.
- **Silent Installations**: Not all installers support silent mode. If an installation hangs, you may need to remove the `--silent` flag.

### Option 2: Using Chocolatey

**Prerequisites:**

- **Chocolatey Installed**: Install Chocolatey by following instructions at [https://chocolatey.org/install](https://chocolatey.org/install).

**Script:**

```powershell
# Ensure that Chocolatey is installed
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Error "Chocolatey is not installed. Please install Chocolatey from https://chocolatey.org/install"
    exit
}

# Update all installed Chocolatey packages
choco upgrade all -y --ignore-unfound
```

*Explanation:*

- **`choco upgrade all`**: Upgrades all installed Chocolatey packages.
- **Flags Used:**
  - `-y`: Automatically confirm all prompts.
  - `--ignore-unfound`: Ignore packages that are not found in the Chocolatey repository.

**Notes:**

- **Administrator Privileges**: Run PowerShell as an administrator.
- **Package Sources**: Only packages installed via Chocolatey will be upgraded.

### Option 3: Generate a List of Installed Software and Check for Updates Manually

Since not all software can be updated via package managers, you can generate a list of installed applications for manual review.

**Script:**

```powershell
# Get list of installed applications from the registry (32-bit and 64-bit)
$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installedApps = foreach ($path in $registryPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayVersion } |
    Select-Object @{Name="Name";Expression={$_.DisplayName}}, @{Name="Version";Expression={$_.DisplayVersion}}, Publisher
}

# Remove duplicates
$installedApps = $installedApps | Sort-Object Name -Unique

# Export to a CSV file
$installedApps | Export-Csv -Path "C:\Reports\InstalledApplications.csv" -NoTypeInformation

Write-Host "Installed applications have been exported to C:\Reports\InstalledApplications.csv"
```

*Explanation:*

- Retrieves installed applications from both 32-bit and 64-bit registry locations.
- Filters entries to include only those with `DisplayName` and `DisplayVersion`.
- Removes duplicate entries.
- Exports the list to a CSV file for review.

**Manual Update Process:**

- Review the CSV file to identify applications and their current versions.
- Visit the vendors' websites to check for newer versions.
- Download and install updates as needed.

**Considerations:**

- **Automating Updates for Non-Package-Managed Software**: Automating updates for software not managed by Winget or Chocolatey is challenging due to varying update mechanisms.
- **Third-Party Tools**: Consider using third-party software management tools designed for enterprise environments (e.g., SCCM, PDQ Deploy).

---

**Additional Script: Combine Both Requirements**

If you want to monitor a process and also ensure it's not installed or updated, you can combine the scripts.

**Script to Continuously Uninstall a Specific Application When Detected**

```powershell
$applicationName = "ExampleApp"
$processName = "exampleapp"

while ($true) {
    # Stop the process if it's running
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "$processName is running. Stopping it..."
        Stop-Process -Name $processName -Force
    }

    # Check if the application is installed
    $appInstalled = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%$applicationName%'" -ErrorAction SilentlyContinue
    if ($appInstalled) {
        foreach ($app in $appInstalled) {
            Write-Host "Uninstalling $($app.Name)..."
            $app.Uninstall()
        }
    }

    Start-Sleep -Seconds 60
}
```

*Explanation:*

- Monitors and stops the specified process.
- Checks if the application is installed and uninstalls it.
- Waits for 60 seconds before repeating.

**Warning:**

- **Use with Extreme Caution**: Uninstalling software automatically can have unintended consequences.
- **Administrative Privileges**: Requires running PowerShell as an administrator.
- **Potential Risks**: Continuously uninstalling software can lead to conflicts, especially if the application is required by the system or other applications.

### Advanced Scripts Part 2

1. **Check for Pending Windows Updates and Install Them**

   ```powershell
   # Requires administrative privileges
   Install-Module PSWindowsUpdate -Force
   Import-Module PSWindowsUpdate
   Get-WindowsUpdate -AcceptAll -Install -AutoReboot
   ```
   *Automatically checks for and installs all pending Windows updates.*

2. **Create a Scheduled Task to Clear Temp Files Daily**

   ```powershell
   $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"Get-ChildItem -Path 'C:\Temp\*' -Recurse | Remove-Item -Force -Recurse`""
   $trigger = New-ScheduledTaskTrigger -Daily -At 3AM
   Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "DailyTempCleanup" -Description "Clears temporary files daily at 3 AM"
   ```
   *Schedules a task to delete all files in the `C:\Temp` directory every day at 3 AM.*

3. **Export a List of Running Processes to a CSV File**

   ```powershell
   Get-Process | Select-Object Name, Id, CPU, WorkingSet | Export-Csv -Path "C:\Reports\RunningProcesses_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
   ```
   *Exports details of all running processes to a CSV file, including CPU and memory usage.*

4. **Monitor Disk Space and Send Email Alert When Low**

   ```powershell
   $threshold = 10GB
   $drive = Get-PSDrive -Name C
   if ($drive.Free -lt $threshold) {
       $emailParams = @{
           To         = "admin@example.com"
           From       = "server@example.com"
           Subject    = "Low Disk Space Alert"
           Body       = "The C drive has less than 10GB of free space."
           SmtpServer = "smtp.example.com"
       }
       Send-MailMessage @emailParams
   }
   ```
   *Monitors the C: drive and sends an email alert if free space drops below 10 GB.*

5. **Enable or Disable USB Storage Devices**

   ```powershell
   # Disable USB Storage
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
   # Enable USB Storage (Uncomment the line below to enable)
   # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3
   ```
   *Disables (or enables) USB storage devices by modifying the registry.*

6. **Fetch and Display Weather Information**

   ```powershell
   $city = "New York"
   $apiKey = "your_api_key_here" # Replace with your OpenWeatherMap API key
   $url = "http://api.openweathermap.org/data/2.5/weather?q=$city&appid=$apiKey&units=metric"
   $weather = Invoke-RestMethod -Uri $url
   Write-Host "Current temperature in $city is $($weather.main.temp)°C with $($weather.weather[0].description)."
   ```
   *Fetches current weather data for a specified city using the OpenWeatherMap API.*

7. **Encrypt and Decrypt Files Using Certificates**

   *Encrypt:*
   ```powershell
   $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*YourName*" }
   $inputFile = "C:\SensitiveData.txt"
   $outputFile = "C:\EncryptedData.enc"
   Protect-CmsMessage -To $cert -Path $inputFile -OutFile $outputFile
   ```
   *Decrypt:*
   ```powershell
   $encryptedFile = "C:\EncryptedData.enc"
   $decryptedFile = "C:\DecryptedData.txt"
   Unprotect-CmsMessage -Path $encryptedFile -OutFile $decryptedFile
   ```
   *Encrypts and decrypts files using a certificate for secure file storage.*

8. **Create a System Restore Point**

   ```powershell
   Checkpoint-Computer -Description "Before Major Update" -RestorePointType "MODIFY_SETTINGS"
   ```
   *Creates a system restore point before making significant system changes.*

9. **Download and Install Chocolatey Packages**

   ```powershell
   # Install Chocolatey (if not already installed)
   Set-ExecutionPolicy Bypass -Scope Process -Force
   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
   Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

   # Install packages
   choco install -y git vscode googlechrome
   ```
   *Installs Chocolatey package manager and uses it to install multiple applications.*

10. **Generate SSH Keys**

    ```powershell
    ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
    ```
    *Generates a new SSH key pair for secure connections.*

---

11. **Check for Orphaned Services and Remove Them**

    ```powershell
    $services = Get-WmiObject win32_service | 
    Where-Object { 
        $_.State -eq 'Stopped' -and $_.StartMode -eq 'Disabled' 
    }
    foreach ($service in $services) {
        Write-Host "Removing service: $($service.Name)"
        sc.exe delete $service.Name
    }
    ```
    *Identifies and removes services that are both stopped and disabled.*

12. **Install IIS and Configure a Basic Website**

    ```powershell
    # Install IIS
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools

    # Create a new website
    Import-Module WebAdministration
    New-Item -Path "IIS:\Sites\MySite" -PhysicalPath "C:\inetpub\wwwroot\MySite" -Bindings @{protocol="http";bindingInformation="*:8080:"}
    ```
    *Installs Internet Information Services (IIS) and sets up a basic website on port 8080.*

13. **Test Network Latency to a Host Over Time**

    ```powershell
    Test-Connection -ComputerName google.com -Count 100 -Delay 1 |
    Select-Object Address, ResponseTime |
    Export-Csv -Path "C:\Reports\PingTest_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
    ```
    *Performs a continuous ping test and logs the response times to a CSV file.*

14. **Disable IPv6 on All Network Adapters**

    ```powershell
    Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding -PassThru
    ```
    *Disables IPv6 protocol on all network adapters to potentially improve network performance.*

15. **Set Time Zone Automatically Based on IP Location**

    ```powershell
    $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/"
    $timeZone = $ipInfo.timezone
    tzutil /s "$timeZone"
    Write-Host "Time zone set to $timeZone"
    ```
    *Sets the system time zone based on the geographical location of your IP address.*

16. **Clone a Git Repository Using PowerShell**

    ```powershell
    git clone https://github.com/user/repository.git "C:\Projects\Repository"
    ```
    *Clones a Git repository into a specified local directory.*

17. **Start a Simple HTTP Server for File Sharing**

    ```powershell
    cd "C:\SharedFolder"
    python -m http.server 8000
    ```
    *Starts a simple HTTP server on port 8000 for sharing files in a directory. Requires Python installed.*

18. **Bulk Convert Images to Another Format**

    ```powershell
    # Requires ImageMagick installed and added to PATH
    Get-ChildItem -Path "C:\Images\*.png" | ForEach-Object {
        $newName = "$($_.BaseName).jpg"
        magick convert $_.FullName "C:\ConvertedImages\$newName"
    }
    ```
    *Converts all PNG images in a folder to JPG format using ImageMagick.*

19. **Monitor a Process and Restart if It Stops**

    ```powershell
    $processName = "notepad"
    while ($true) {
        if (-not (Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
            Write-Host "$processName has stopped. Restarting..."
            Start-Process $processName
        }
        Start-Sleep -Seconds 60
    }
    ```
    *Continuously monitors Notepad and restarts it if it closes.*

20. **List All USB Devices Connected to the System**

    ```powershell
    Get-PnpDevice -Class USB -Status OK | Select-Object FriendlyName, InstanceId
    ```
    *Lists all connected USB devices along with their friendly names and instance IDs.*


### Advanced Scripts Part 3


1. **Batch Rename Files in a Directory**
   ```powershell
   Get-ChildItem -Path "C:\Folder\*.txt" | 
   Rename-Item -NewName { $_.Name -replace 'OldText', 'NewText' }
   ```
   *Renames all `.txt` files by replacing 'OldText' with 'NewText' in filenames.*

2. **Backup and Restore Registry Keys**

   *Backup:*
   ```powershell
   reg export "HKCU\Software\MyApp" "C:\Backup\MyApp.reg"
   ```
   *Restore:*
   ```powershell
   reg import "C:\Backup\MyApp.reg"
   ```
   *Backs up and restores specific registry keys.*

3. **Automate Windows Updates**
   ```powershell
   Install-Module PSWindowsUpdate -Force
   Import-Module PSWindowsUpdate
   Get-WindowsUpdate -Install -AcceptAll -AutoReboot
   ```
   *Installs all available Windows updates and reboots automatically.*

4. **Retrieve Recent Error Event Logs**
   ```powershell
   Get-EventLog -LogName Application -EntryType Error -Newest 50
   ```
   *Fetches the 50 most recent error entries from the Application event log.*

5. **Create a New Local User Account**
   ```powershell
   $Password = Read-Host -AsSecureString "Enter Password"
   New-LocalUser -Name "NewUser" -Password $Password -FullName "Full Name" -Description "Description"
   Add-LocalGroupMember -Group "Administrators" -Member "NewUser"
   ```
   *Creates a new local user and adds them to the Administrators group.*

6. **Monitor a Folder for Changes (Full Script)**
   ```powershell
   $folder = "C:\FolderToMonitor"
   $watcher = New-Object System.IO.FileSystemWatcher $folder -Property @{
       IncludeSubdirectories = $true
       NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite'
       Filter = "*.*"
   }
   $onChange = Register-ObjectEvent $watcher 'Changed' -Action {
       Write-Host "File Changed: $($Event.SourceEventArgs.FullPath)"
   }
   ```
   *Monitors a folder and outputs a message when a file is changed.*

7. **List Open Network Ports and Processes**
   ```powershell
   ## List Open Network Ports and Processes
   Get-NetTCPConnection | Select-Object LocalAddress, RemoteAddress, LocalPort, State, @{
    	Name="Process"; Expression={
    		(Get-Process -Id $_.OwningProcess).ProcessName
    	}
   }, @{
    	Name="P-ID"; Expression={
    		(Get-Process -Id $_.OwningProcess).Id
    	}
   }
   ```
   *Displays all TCP connections with associated processes.*

8. **Disable Specific Startup Programs**
   ```powershell
   $startupPrograms = @("Program1", "Program2")
   Get-CimInstance Win32_StartupCommand | 
   Where-Object { $startupPrograms -contains $_.Name } | 
   Remove-CimInstance
   ```
   *Disables specified programs from starting automatically.*

9. **Generate a Secure Random Password**
   ```powershell
   Add-Type -AssemblyName System.Web
   $password = [System.Web.Security.Membership]::GeneratePassword(16,4)
   Write-Host "Generated Password: $password"
   ```
   *Generates a random password with specified length and number of non-alphanumeric characters.*

10. **Test Internet Connectivity**
    ```powershell
    if (Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet) {
        Write-Host "Internet is available."
    } else {
        Write-Host "No internet connection."
    }
    ```
    *Checks if the internet is accessible by pinging Google's DNS server.*

---

11. **Clean Temporary Files (Full Script with Confirmation)**
    ```powershell
    $tempFolders = @("C:\Windows\Temp", "$env:UserProfile\AppData\Local\Temp")
    foreach ($folder in $tempFolders) {
        Write-Host "Cleaning $folder..."
        Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    Write-Host "Temporary files cleaned."
    ```
    *Deletes files from system and user temporary directories.*

12. **Retrieve External IP Address**
    ```powershell
    $externalIP = (Invoke-WebRequest -Uri "https://api.ipify.org").Content
    Write-Host "External IP Address: $externalIP"
    ```
    *Gets the machine's external IP address.*

13. **Bulk Uninstall Applications (Use with Caution)**
    ```powershell
    $appsToRemove = @("App1", "App2")
    foreach ($app in $appsToRemove) {
        Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%$app%'" | ForEach-Object {
            $_.Uninstall()
            Write-Host "$($_.Name) has been uninstalled."
        }
    }
    ```
    *Uninstalls applications matching specified names.*

14. **Automated Backup Script with Date Stamp**
    ```powershell
    $source = "C:\ImportantData"
    $destination = "D:\Backups\ImportantData_$((Get-Date).ToString('yyyyMMdd')).zip"
    Compress-Archive -Path $source -DestinationPath $destination
    Write-Host "Backup created at $destination"
    ```
    *Creates a ZIP backup of a folder with a date-stamped filename.*

15. **Set Folder Permissions for a User**
    ```powershell
    $folderPath = "C:\SecureFolder"
    $user = "DOMAIN\UserName"
    $acl = Get-Acl $folderPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $folderPath -AclObject $acl
    Write-Host "Permissions set for $user on $folderPath"
    ```
    *Grants full control permissions to a specified user for a folder.*

16. **Optimize System Performance (Full Script)**
    ```powershell
    # Stop unnecessary services
    $servicesToStop = @("Spooler", "SysMain")
    foreach ($service in $servicesToStop) {
        if ((Get-Service -Name $service).Status -eq "Running") {
            Stop-Service -Name $service -Force
            Set-Service -Name $service -StartupType Disabled
            Write-Host "$service stopped and disabled."
        }
    }
    # Disable startup programs
    $startupItems = @("OneDrive", "Skype")
    Get-CimInstance Win32_StartupCommand | 
    Where-Object { $startupItems -contains $_.Name } | 
    Remove-CimInstance
    Write-Host "Selected startup programs disabled."
    ```
    *Stops unnecessary services and disables specified startup programs.*

17. **Find and Remove Duplicate Files (Use with Caution)**
    ```powershell
    $hashTable = @{}
    Get-ChildItem -Path "C:\Folder" -Recurse -File | ForEach-Object {
        $hash = (Get-FileHash $_.FullName).Hash
        if ($hashTable.ContainsKey($hash)) {
            Remove-Item -Path $_.FullName -Force
            Write-Host "Removed duplicate: $($_.FullName)"
        } else {
            $hashTable[$hash] = $_.FullName
        }
    }
    ```
    *Finds and removes duplicate files based on hash values.*

18. **Configure Firewall to Block an IP Address**
    ```powershell
    $blockedIP = "203.0.113.0"
    New-NetFirewallRule -DisplayName "Block $blockedIP" -Direction Inbound -RemoteAddress $blockedIP -Action Block
    Write-Host "Firewall rule added to block $blockedIP"
    ```
    *Creates a firewall rule to block inbound traffic from a specific IP.*

19. **Check SSL Certificate Expiry Date**
    ```powershell
    ## Check SSL Certificate Expiry Date
    $hostname = "example.com"
    $port = 443
    $client = New-Object System.Net.Sockets.TcpClient(
        $hostname, $port
    )
    $stream = $client.GetStream()
    $sslStream = New-Object System.Net.Security.SslStream(
        $stream, $false, ({$true})
    )
    $sslStream.AuthenticateAsClient($hostname)
    $cert = $sslStream.RemoteCertificate
    $sslStream.Dispose()
    $client.Close()
    $expiryDate = [DateTime]::Parse($cert.GetExpirationDateString())
    Write-Host "SSL Certificate for $hostname expires on $expiryDate"
    ```
    *Checks the SSL certificate expiry date for a given hostname.*

20. **Generate a System Audit Report (Full Script)**

```powershell
$hive="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
$report = @{
    "ComputerName" = $env:COMPUTERNAME
    "OSVersion" = (
        Get-CimInstance Win32_OperatingSystem
    ).Version
    
    "InstalledApplications" = Get-ItemProperty $hive |
        Select-Object DisplayName, DisplayVersion
    
    "RunningServices" = Get-Service | 
        Where-Object {$_.Status -eq "Running"} | 
        Select-Object Name, DisplayName
}
$report | ConvertTo-Json | Out-File -FilePath "C:\SysAudits\$(Get-Date -Format yyyyMMdd).json"
Write-Host "System audit report generated at C:\SysAudits\$(Get-Date -Format yyyyMMdd).json"
```
*Generates a comprehensive system audit report and saves it as a JSON file.*


### Advanced Scripts Part 4


1. **Update All Installed PowerShell Modules**
   ```powershell
   Get-InstalledModule | Update-Module
   ```
   *Updates all installed PowerShell modules to their latest versions.*

2. **Search for Text Within Files**
   ```powershell
   Select-String -Path "C:\path\to\files\*.txt" -Pattern "search text"
   ```
   *Finds specific text patterns within files, useful for code searches.*

3. **Find Large Files on a Drive**
   ```powershell
   Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
   Where-Object { $_.Length -gt 1GB } |
   Sort-Object Length -Descending
   ```
   *Identifies files larger than 1 GB, helping to free up disk space.*

4. **Monitor Real-Time CPU Usage**
   ```powershell
   Get-Counter '\Processor(_Total)\% Processor Time' -Continuous
   ```
   *Displays real-time CPU usage statistics.*

5. **Kill a Process by Name**
   ```powershell
   Get-Process notepad | Stop-Process -Force
   ```
   *Terminates all instances of Notepad.*

6. **List Installed Programs**
   ```powershell
   Get-WmiObject -Class Win32_Product | Select-Object Name, Version
   ```
   *Lists all installed applications and their versions.*

7. **Copy Files While Preserving Directory Structure**
   ```powershell
   Copy-Item -Path C:\Source\* -Destination D:\Backup\ -Recurse
   ```
   *Copies files and folders recursively to a backup location.*

8. **Download a File from the Internet**
   ```powershell
   $SrcURI="https://example.com/file.zip"
   $OutFile="C:\Downloads\file.zip"
   Invoke-WebRequest -Uri $SrcURI -OutFile $OutFile
   ```
   *Downloads a file from a URL to a specified directory.*

9. **Check Available Disk Space**
   ```powershell
   Get-PSDrive C | Select-Object Used, Free, @{Name="UsedGB";Expression={$_.Used/1GB}}, @{Name="FreeGB";Expression={$_.Free/1GB}}
   ```
   *Displays used and free space on the C: drive in gigabytes.*

10. **Set Execution Policy**
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    ```
    *Allows running local scripts and requires remote scripts to be signed.*

11. **Compress a Folder into a ZIP File**
    ```powershell
    Compress-Archive -Path C:\Source\* -DestinationPath C:\Archives\archive.zip
    ```
    *Creates a ZIP archive of a folder's contents.*

12. **Extract a ZIP File**
    ```powershell
    Expand-Archive -Path C:\Archives\archive.zip -DestinationPath C:\Destination
    ```
    *Extracts the contents of a ZIP file to a specified folder.*

13. **List Services and Their Status**
    ```powershell
    Get-Service | Select-Object Name, Status
    ```
    *Displays all services along with their current status (Running or Stopped).*

14. **Start or Stop a Service**
    ```powershell
    Start-Service -Name "Spooler"
    Stop-Service -Name "Spooler"
    ```
    *Starts or stops the Print Spooler service.*

15. **Create a Scheduled Task**
    ```powershell
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File 'C:\Scripts\Backup.ps1'"
    $trigger = New-ScheduledTaskTrigger -Daily -At 2AM
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "DailyBackup"
    ```
    *Schedules a PowerShell script to run daily at 2 AM.*

16. **Generate a System Information Report**
    ```powershell
    Get-ComputerInfo | Out-File -FilePath C:\Reports\SystemInfo.txt
    ```
    *Creates a text file containing detailed system information.*

17. **Set an Environment Variable**
    ```powershell
    [Environment]::SetEnvironmentVariable(
        "VariableName", 
        "Value", 
        "User"
    )
    ```
    *Sets a user-level environment variable.*

18. **Check PowerShell Version**
    ```powershell
    $PSVersionTable.PSVersion
    ```
    *Displays the current PowerShell version installed.*

19. **Enable Remote Desktop**
    ```powershell
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    ```
    *Enables Remote Desktop connections and configures the firewall accordingly.*

20. **Search for Installed Modules**
    ```powershell
    Find-Module -Name "*ModuleName*"
    ```
    *Searches the PowerShell Gallery for modules matching a pattern.*


