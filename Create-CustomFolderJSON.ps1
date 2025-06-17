
# RemotePath can be folder or file.
# LocalBackupFolder is optional, if not specified, the current BackupPath will be used as LocalBackupFolder.
# Possible special Placeholders are available in the LocalBackupFolder path.
# {BACKUPLOCATION} - The path to the backup location.
# {DATE-yyyyMMdd} - The current date in the format yyyyMMdd.
# {DATE-yyyyMMddHHmmss} - The current date and time in the format yyyyMMddHHmmss.
# {COMPUTERNAME} - The computer name.
$CustomFolders = @{
    custom = @{
        RemotePath = "/var/custom"
        LocalBackupFolder = "{BACKUPLOCATION}\custom.{DATE-yyyyMMdd}"
    }
    acme = @{
        RemotePath = "/conf/acme"
        LocalBackupFolder = '\\server\share\acme'
    }
    apiBackup = @{
        RemotePath = "/usr/local/share/pfSense-pkg-API/backup.json"
        LocalBackupFolder = "{BACKUPLOCATION}"
        LocalBackupFileName = "backup-{COMPUTERNAME}-{DATE-yyyyMMddHHmmss}.json"
    }
}

$json = ConvertTo-Json -InputObject $CustomFolders -Depth 4
$jsonCompressed = ConvertTo-Json -InputObject $CustomFolders -Depth 4 -Compress

# Use parameter [string]$CustomFolderJSONString
$jsonCompressed | Set-Clipboard
# Use parameter [string]$CustomFolderJSONFile
$json | Out-File -FilePath "CustomFolders.json" -Encoding utf8

# $fileDate = Get-Date -Format yyyyMMddHHmmss
# Rename-Item -Path ($BackupLocation + "\config.xml") -NewName $("config-" + $HostName.ToLower() + "-" + $fileDate + ".xml")
# Rename-Item -Path ($BackupLocation + "\backup.json") -NewName $("backup-" + $HostName.ToLower() + "-" + $fileDate + ".json")

