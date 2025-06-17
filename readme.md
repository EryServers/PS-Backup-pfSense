# Installing WinSCP from PowerShell Gallery

You can install the WinSCP PowerShell module from the PowerShell Gallery using the following command:

Run as Administrator:
```powershell
Install-Module -Name WinSCP -Scope AllUsers
```

## Common Parameters

- `-Scope`: Specifies whether to install for the current user (`CurrentUser`) or all users (`AllUsers`).
- `-Force`: Installs the module without prompting for confirmation.
- `-AllowClobber`: Allows the cmdlet to overwrite existing commands.
- `-RequiredVersion`: Installs a specific version of the module.

**Example:**

```powershell
Install-Module -Name WinSCP -Scope CurrentUser -Force
```

For more details, see the [PowerShell Gallery WinSCP page](https://www.powershellgallery.com/packages/WinSCP).

## Usage Examples

### Basic Usage

```powershell
.\Backup-pfSense.ps1 -pfSenseMachine "pfsense01" `
    -SshHostKeyFingerprint "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx" `
    -BackupPath "C:\Backups\pfSense" `
    -PrivateKeyPath "C:\Keys\id_rsa" `
    -Username "pfbackup"
```

### With Email Notification

```powershell
.\Backup-pfSense.ps1 -pfSenseMachine "pfsense01" `
    -SshHostKeyFingerprint "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx" `
    -BackupPath "C:\Backups\pfSense" `
    -PrivateKeyPath "C:\Keys\id_rsa" `
    -Username "pfbackup" `
    -MailRecipients "admin@example.com" `
    -MailFrom "backup@example.com" `
    -MailsmtpServer "smtp.example.com"
```

### With Discord Notification

```powershell
.\Backup-pfSense.ps1 -pfSenseMachine "pfsense01" `
    -SshHostKeyFingerprint "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx" `
    -BackupPath "C:\Backups\pfSense" `
    -PrivateKeyPath "C:\Keys\id_rsa" `
    -Username "pfbackup" `
    -DiscordHookUrl "https://discord.com/api/webhooks/..." `
    -DiscordThreadId "1234567890"
```

Currently nothing will be sent to Discord, if Mail is not used.
Working on it...

### With Custom Folder Backup

```powershell
.\Backup-pfSense.ps1 -pfSenseMachine "pfsense01" `
    -SshHostKeyFingerprint "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx" `
    -BackupPath "C:\Backups\pfSense" `
    -PrivateKeyPath "C:\Keys\id_rsa" `
    -Username "pfbackup" `
    -CustomFolderJSONFile "C:\Path\to\customfolders.json"
```

> **Tip:** Use `-Verbose` for more detailed output.

---

**Required Parameters:**
- `-pfSenseMachine`  
- `-SshHostKeyFingerprint`  
- `-BackupPath`  
- `-PrivateKeyPath`  
- `-Username`  

Optional parameters include `-MailRecipients`, `-MailFrom`, `-MailsmtpServer`, `-DiscordHookUrl`, `-DiscordThreadId`, `-CustomFolderJSONFile`, and `-CustomFolderJSONString`.
