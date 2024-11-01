# PowerShell One-O-One

A comprehensive list of powerful and useful PowerShell commands for daily use and Windows automation. Whether you're a beginner or an advanced user, this repository will help you enhance your productivity by providing a curated collection of commonly used commands, tips, and scripts to automate tasks on Windows.

## Jump right into:

- [**My Favorite Utils**](/pwsh-utils.md)
- [Basic Commands](#basic-commands)
- [Automation Snippets](#automation-examples)
- [Useful Stuff](#useful-snippets)

- [Contributing](#contributing)
- [License](#license)
- [Further Reading](#further-reading)

## Introduction

PowerShell is a powerful scripting language and command-line shell designed especially for system administrators. This repository compiles a list of commands that can assist in everyday tasks, such as file manipulation, process management, networking, and automation. Use these commands to simplify and streamline your workflow on Windows.

## Features

- **Curated PowerShell Commands:** A collection of frequently used and effective commands.
- **Automation Tips:** Scripts and examples to automate repetitive tasks.
- **Organized by Use Cases:** Commands are categorized for easy lookup (file system, networking, processes, etc.).
- **Beginner to Advanced:** Suitable for users of all levels.

## Getting Started

### Prerequisites

- **PowerShell 5.1 or later** is required to run the commands and scripts in this repository. To check your version, run:

  ```powershell
  $PSVersionTable.PSVersion
  ```

- For the latest PowerShell, you can download [PowerShell Core](https://github.com/PowerShell/PowerShell#get-powershell).

Alternatively, you can download the repository as a ZIP file from GitHub and extract it locally.

### Recommended is using [Powershell 7.4](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4) which adds handy extra features.

- For this installation guide for **Powershell 7.4** is [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget) required. Make sure you've installed it on your system.

- Searched for the latest version

```powershell
winget search Microsoft.PowerShell
```

_Output_: 

```markdown
Name               Id                           Version   Source
-----------------------------------------------------------------
PowerShell         Microsoft.PowerShell         7.4.5.0   winget
PowerShell Preview Microsoft.PowerShell.Preview 7.5.0.3   winget
```

- Install Powershell 7.4 via winget

```powershell
# install the latest pwsh version via winget

winget install --id Microsoft.PowerShell --source winget
winget install --id Microsoft.PowerShell.Preview --source winget
```

--- 

## Basic Commands

Here are a few basic but powerful PowerShell commands you’ll find in this repository:

- **Get list of running processes:**

  ```powershell
  Get-Process
  ```

- **Check disk space:**

  ```powershell
  Get-PSDrive -PSProvider FileSystem
  ```

- **List files in a directory:**

  ```powershell
  Get-ChildItem -Path "C:\path\to\directory"
  ```

## Automation Examples

**Automating File Backup:**

  ```powershell
  $source = "C:\path\to\source"
  $destination = "D:\path\to\backup"
  Copy-Item -Path $source -Destination $destination -Recurse
  ```

**Scheduled Task Creation:**

```powershell
$scrpt='-File C:\path\to\script.ps1'
$tsk = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $scrpt
$trgr = New-ScheduledTaskTrigger -Daily -At 6AM
Register-ScheduledTask -Action $tsk -Trigger $trgr -TaskName "DailyTask"
```

## Useful Snippets

- **Get network adapter information:**

  ```powershell
  Get-NetAdapter
  ```

- **Kill a specific process:**

  ```powershell
  Stop-Process -Name "processname"
  ```

- **Check event logs for errors:**

  ```powershell
  Get-EventLog -LogName System -EntryType Error -Newest 10
  ```

For a full list of commands and examples, check the `commands/` folder in this repository.

## Contributing

Contributions are welcome! If you have useful PowerShell scripts or commands that you would like to share, please follow these steps:

1. Fork the repository.
2. Create a new branch:

   ```bash
   git checkout -b feature-branch
   ```

3. Commit your changes:

   ```bash
   git commit -m "Add a new PowerShell command"
   ```

4. Push to the branch:

   ```bash
   git push origin feature-branch
   ```

5. Create a Pull Request.

Make sure your contributions are well-documented and tested where applicable.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Further Reading

- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [PowerShell Gallery](https://www.powershellgallery.com/)
- [PowerShell Core GitHub Repository](https://github.com/PowerShell/PowerShell)
