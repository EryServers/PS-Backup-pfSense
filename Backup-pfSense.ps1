<#
.SYNOPSIS
    Backup pfSense configuration and custom files using WinSCP.
.VERSION
    0.04-adx
    0.03-adx: Added support for custom folder backup.
    0.02-adx: Added support for SFTP and private key authentication.
    0.01-adx: Initial version.
    
    This script is a part of the pfSense module project, and is used to backup pfSense configuration files.
.DESCRIPTION
    This script connects to a pfSense machine using WinSCP, downloads the configuration file and custom files, and saves them to a specified backup location.
    It uses SSH private key authentication for secure access.    
.PARAMETER pfSenseMachine
    NetBios name of pfSense machine. This is part of the full DNS name, and part of the backup-folder.
.PARAMETER SshHostKeyFingerprint
    Fingerprint of SSH host. Unique for each machine.
.EXAMPLE
    .\Backup-pfSense.ps1
    Run first time to create a new .xml-file, or when default .xml filename is used.
.EXAMPLE
    .\Backup-pfSense.ps1 -pfSenseMachine "pfsense01" -SshHostKeyFingerprint "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"
    Run with parameters to specify the pfSense machine and SSH host key fingerprint.
    For running with setttings from .xml-files that differs from default filename.
.EXAMPLE
    .\Backup-pfSense.ps1 -Verbose
    For more information to console, when debugging or problems with servers.
.NOTES
    Author: Eryniox
    Date:   April 2015
.LINK
    https://github.com/Eryniox/
#>

#requires -Modules WinSCP

#region Parameters, Variables, Trap and required snapins
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$pfSenseMachine,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$SshHostKeyFingerprint,

    [Parameter(Mandatory = $true, Position = 2)]
    [string]$BackupPath,

    [Parameter(Mandatory = $true, Position = 3)]
    [string]$PrivateKeyPath,

    [Parameter(Mandatory = $true, Position = 4)]
    [string]$Username,

    [Parameter(Mandatory = $false, Position = 5)]
    [string[]]$MailRecipients,

    [Parameter(Mandatory = $false, Position = 6)]
    [string]$MailFrom,

    [Parameter(Mandatory = $false, Position = 7)]
    [string]$MailsmtpServer,

    [Parameter(Mandatory = $false, Position = 8)]
    [string]$DiscordHookUrl,

    [Parameter(Mandatory = $false, Position = 9)]
    [string]$DiscordThreadId,

    [Parameter(Mandatory = $false, Position = 10)]
    [string]$CustomFolderJSONFile,

    [Parameter(Mandatory = $false, Position = 11)]
    [string]$CustomFolderJSONString
)
#End CmdletBinding
# adm-CustomAttributeText13: SshHostKeyFingerprint
# These parameters are for adx-version of the script, and are not used in this version.
# iskipf ($Context.TargetObject.Class -eq "computer") {[string]$pfSenseMachine = $Context.TargetObject.Get("cn")} else {[string]$pfSenseMachine = $Context.GetParameterValue("param-pfSenseMachine")}
# iskipf ($Context.TargetObject.Class -eq "computer") {[string]$SshHostKeyFingerprint = $Context.TargetObject.Get("adm-CustomAttributeText13")} else {[string]$SshHostKeyFingerprint = $Context.GetParameterValue("param-SshHostKeyFingerprint")}
# [string]$pfSenseMachine = $Context.GetParameterValue("param-pfSenseMachine")
# [string]$SshHostKeyFingerprint = $Context.GetParameterValue("param-SshHostKeyFingerprint")
# [string]$BackupPath = $Context.GetParameterValue("param-BackupPath")
# [string]$PrivateKeyPath = $Context.GetParameterValue("param-PrivateKeyPath")
# [string]$Username = $Context.GetParameterValue("param-Username")
# [string[]]$MailRecipients = $Context.GetParameterValue("param-MailRecipients") -split ";"
# [string]$MailFrom = $Context.GetParameterValue("param-MailFrom")
# [string]$MailsmtpServer = $Context.GetParameterValue("param-MailsmtpServer")
# [string]$DiscordHookUrl = $Context.GetParameterValue("param-DiscordHookUrl")
# [string]$DiscordThreadId = $Context.GetParameterValue("param-DiscordThreadId")
# [string]$CustomFolderJSONFile = $Context.GetParameterValue("param-CustomFolderJSONFile")
# [string]$CustomFolderJSONString = $Context.GetParameterValue("param-CustomFolderJSONString")

#region Context outside Adaxes
$UseAdmService = $false # $true/$false - used for ex.: New-Object "Softerra.Adaxes.Adsi.AdsPath" $managedDomainsPath

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSProvideDefaultParameterValue", "ContextVersion")]
[version]$ContextVersion = "2.01"
# To run script outside Adaxes:
If (!($Context)) {
    # $UseAdmService = $true
    $Context = New-Object PSObject
    $Context | Add-Member NoteProperty Action "Debug"
    $Context | Add-Member NoteProperty TargetObject $null
    $Context | Add-Member ScriptMethod -Name  "LogMessage" -Value { Param($Tekst, $Type) Write-Host ("LM[" + $Type + "]: " + $Tekst) }
    $BindDomainName = (Get-CimInstance Win32_ComputerSystem).Domain
} ElseIf (!($BindDomainName) -and "%adm-DomainDN%" -notlike "*adm-DomainDN*") {
    $BindDomainName = "%adm-DomainDN%"
}

If ($UseAdmService) {
    try { $NULL = [Reflection.Assembly]::GetAssembly("Softerra.Adaxes.Adsi.AdmNamespace") }
    catch {
        try { [Reflection.Assembly]::LoadWithPartialName("Softerra.Adaxes.Adsi") | Out-Null }
        catch {}
    }
    try { $NULL = [Reflection.Assembly]::GetAssembly("Softerra.Adaxes.Adsi.AdmNamespace") }
    catch {
        Write-Error "Can't add Assembly Softerra.Adaxes.Adsi.AdmNamespace! Aborting."
        Return
    }
    try {
        # Connect to the Adaxes service:
        If ($Context.PSobject.Methods.Name -notcontains "admNS")
        {
            $Context | Add-Member NoteProperty admNS ( New-Object "Softerra.Adaxes.Adsi.AdmNamespace" )
            $Context | Add-Member NoteProperty admService ( $Context.admNS.GetServiceDirectly("localhost") )
        }
    }
    catch {
        Write-Error "Can't add members to Context - Trying to continue."
    }
    try {
        If ($Context.PSobject.Methods.Name -notcontains "GetWellKnownContainerPath")
        {
            $Context | Add-Member ScriptMethod GetWellKnownContainerPath {
                $this.admService.Backend.GetConfigurationContainerPath($args[0]) }
            $Context.LogMessage("< add: GetWellKnownContainerPath >", "Information")
        }
        If ($Context.PSobject.Methods.Name -notcontains "BindToObject")
        {
            $Context | Add-Member ScriptMethod BindToObject {
                param ( [Parameter(Mandatory=$true)]$AdaxesPath )
                (, $this.admService.OpenObject($AdaxesPath.ToString(), $NULL, $NULL, 0) ) }
            $Context.LogMessage("< add: BindToObject >", "Information")
        }
        If ($Context.PSobject.Methods.Name -notcontains "BindToObjectEx")
        {
            $Context | Add-Member ScriptMethod BindToObjectEx {
                param ( [Parameter(Mandatory=$true)]$AdaxesPath, [bool]$None = $True )
                (, $this.BindToObject($AdaxesPath) ) }
            $Context.LogMessage("< add: BindToObjectEx >", "Information")
        }
        #$Context.TargetObject = $Context.BindToObject("Adaxes://$dn")
    }
    catch {
        Write-Error "Can't add members to Context - Trying to continue."
    }
}
# Examples:
#$domain = $Context.BindToObjectEx("Adaxes://" + $BindDomainName,$True)
#$wellknownContainerPath = $Context.GetWellKnownContainerPath("ServiceSettings")
#$serviceSettings = $Context.BindToObject($wellknownContainerPath)
#$serviceSettings.MailSettings.From
#endregion Context outside Adaxes


try { $Result = (([System.Net.Dns]::GetHostAddresses($pfSenseMachine) | Select-Object -expandproperty IPAddressToString) -join ",") -match "\." }
catch {$Result = $false}
If ($Result) { #All OK
} Else { throw "$pfSenseMachine is not a valid NetBIOS name (can't find computer in DNS)." }
If ($SshHostKeyFingerprint -match "^ssh-(rsa|ed25519).+") { #All OK
} Else { throw "$SshHostKeyFingerprint is not a valid ssh host fingerprint-key" }


$Context.LogMessage("pfSenseMachine = $pfSenseMachine - SshHostKeyFingerprint = $SshHostKeyFingerprint", "Information")

$Version = [version]"0.04.0"

# Not really needed, because of #requires, but for consistency with other scripts:
try { Import-Module -Name WinSCP }
catch {
    $Context.LogMessage("Can't import module WinSCP - aborting!", "Error")
    Return
}
#EndRegion Parameters, Variables, Trap and required snapins

#region Classes
class pfSenseParams {
    [string] $pfSenseMachine
    [string] $SshHostKeyFingerprint
    [string] $BackupPath
    [string] $PrivateKeyPath
    [string] $Username
    [WinSCP.SessionOptions] $sessionOptions = [WinSCP.SessionOptions]::new()
    # [System.Object] $sessionOptions = (New-WinSCPSessionOption -HostName "temp")
    [string] $CustomFolderJSONFile
    [string] $CustomFolderJSONString
    [hashtable] $CustomFolders = @{}

    # Constructor
    pfSenseParams([string]$pfSenseMachine, [string]$SshHostKeyFingerprint, [string]$BackupPath) {
        $this.pfSenseMachine = $pfSenseMachine
        $this.SshHostKeyFingerprint = $SshHostKeyFingerprint
        $this.BackupPath = $BackupPath.Trim()
    }


    #Hidden Property-methods
    hidden $__class_init__ = $(
        $this | Add-Member -MemberType ScriptProperty -Name BackupLocation -Value { # get
            return ( $this.BackupPath.Trim().TrimEnd("\") + "\" + $this.pfSenseMachine )
        } -SecondValue { param ( $arg ) } # set . don't care about the set
        $this | Add-Member -MemberType ScriptProperty -Name HostName -Value { # get
            return ([System.Net.Dns]::GetHostByName($this.pfSenseMachine).Hostname)
        } -SecondValue { param ( $arg ) } # set . don't care about the set
    )
    
    # Methods
    [void] SetWinSCPParams() {
        # This method is used to set the WinSCP session options.
        $this.sessionOptions.UserName = $this.Username
        $this.sessionOptions.SshPrivateKeyPath = $this.PrivateKeyPath
        # $this.sessionOptions.Protocol = [WinSCP.Protocol]::SFTP
        $this.sessionOptions.Protocol = "Sftp" # Use SFTP protocol - and keep it simple
        $this.sessionOptions.HostName = $this.HostName
        $this.sessionOptions.SshHostKeyFingerprint = $this.SshHostKeyFingerprint
    }

    [void] AddCustomFolder() {
        # This method is used to add a custom folder to the CustomFolders hashtable.
        if ($this.CustomFolderJSONFile) {
            $this.CustomFolderJSONString = Get-Content -Path $this.CustomFolderJSONFile -Raw
        } elseif ($this.CustomFolderJSONString) {
        } else {
            throw "No custom folder JSON file or string provided."
        }
        $CustomFoldersObj = ConvertFrom-Json -InputObject $this.CustomFolderJSONString
        foreach ($name in $CustomFoldersObj.PSObject.Properties.Name) {
            $remotePath = $CustomFoldersObj.$name.RemotePath
            if ($CustomFoldersObj.$name.LocalBackupFolder) {
                $localBackupFolder = $CustomFoldersObj.$name.LocalBackupFolder
            } else {
                $localBackupFolder = $this.BackupLocation
            }
            $this.CustomFolders[$name] = @{
                RemotePath = $remotePath.Trim().TrimEnd("/")
                LocalBackupFolder = $this.PlaceholderReplace($localBackupFolder)
            }
            if ($CustomFoldersObj.$name.LocalBackupFileName) {
                $LocalBackupFileName = $CustomFoldersObj.$name.LocalBackupFileName
                $LocalBackupFileName = $this.PlaceholderReplace($LocalBackupFileName)
                $this.CustomFolders[$name].LocalBackupFileName = $LocalBackupFileName
            }
        }
    }

    [string] PlaceholderReplace([string]$inputString) {
        # This method replaces placeholders in the input string with actual values.
        $inputString = $inputString -replace "{BACKUPLOCATION}", $this.BackupLocation
        $inputString = $inputString -replace "{DATE-yyyyMMdd}", (Get-Date -Format yyyyMMdd)
        $inputString = $inputString -replace "{DATE-yyyyMMddHHmmss}", (Get-Date -Format yyyyMMddHHmmss)
        $inputString = $inputString -replace "{COMPUTERNAME}", $this.pfSenseMachine
        $inputString = $inputString.Trim().TrimEnd("\")
        return $inputString
    }
}

class MailLog {
    # Properties
    [array] $MailMessage = @()
    [string] $MailSubject = "Backup of "
    [string[]] $recipients
    [string] $from
    [string] $smtpServer

    # Constructor
    MailLog( [string] $smtpServer, 
             [string[]]$recipients, 
             [string]$from, 
             [string]$subjectAdd) {
        $this.MailSubject += $subjectAdd
        $this.smtpServer = $smtpServer
        $this.recipients = $recipients
        $this.from = $from
    }

    # Methods
    [void] AddMessage([string]$message) {
        $this.MailMessage += $message
    }

    [string] GetMailMessage() {
        return ($this.MailMessage -join "`r`n")
    }

    [void] SendMail() {
        if ($this.smtpServer -and $this.recipients -and $this.from) { # All good
        } else {
            Write-Host "SMTP server, recipients or from address not set. Not sending email."
            return
        }
        $Params = @{
            SmtpServer = $this.smtpServer
            Subject = $this.MailSubject
            Body = $this.GetMailMessage()
            To = $this.recipients
            From = $this.from
        }
        Send-MailMessage @Params
        # Send-adxMail @Params
    }
}

class DiscordWebHook {
    [string] $HookUrl
    [string] $ThreadId
    [string] $Content
    [string] $Username = "pfSense Backup Bot"

    DiscordWebHook([string]$hookUrl, [string]$threadId, [string]$content) {
        $this.HookUrl = $hookUrl
        $this.ThreadId = $threadId
        $this.Content = $content
    }

    [void] Send() {
        if ($this.HookUrl -and $this.Content) { # All good
        } else {
            Write-Host "Hook URL or content not set. Not sending Discord message."
            return
        }
        # If the content is too long, it will be split into chunks of max 2000 characters.}
        $maxLength = 2000
        $chunks = [regex]::Matches($this.Content, "(.|`r|`n){1,$maxLength}") | ForEach-Object { $_.Value }

        $Payload = @{
            content = ""
            username = $this.Username
        }
        If ($this.ThreadId) {
            $ThreadURL = $this.HookUrl + "?thread_id=" + $this.ThreadId
        } Else {
            $ThreadURL = $this.HookUrl
        }
        foreach ($chunk in $chunks) {
            $Payload.content  = $chunk
            Invoke-WebRequest -Uri $ThreadURL -Method Post -Body ($Payload | ConvertTo-Json) -ContentType "application/json"
        }
    }
}

#EndRegion Classes

function Send-adxMail {
    param (
        [string]$SmtpServer,
        [string[]]$To,
        [string]$From,
        [string]$Subject,
        [string]$Body
    )
    $To = $To -join ", "
    # Bind to the 'ServiceSettings' container
    $wellknownContainerPath = $Context.GetWellKnownContainerPath("ServiceSettings")
    $serviceSettings = $Context.BindToObject($wellknownContainerPath)
    # Send mail
    $serviceSettings.MailSettings.SendMail($To, $Subject, $Body, $Null, $From, $Null, $Null)
}

$ParamObj = [pfSenseParams]::new($pfSenseMachine, $SshHostKeyFingerprint, $BackupPath)
$ParamObj.PrivateKeyPath = $PrivateKeyPath
$ParamObj.Username = $Username

if ($CustomFolderJSONFile -or $CustomFolderJSONString) {
    $Context.LogMessage("Using custom folder JSON file or string.", "Information")
    $ParamObj.CustomFolderJSONFile = $CustomFolderJSONFile
    $ParamObj.CustomFolderJSONString = $CustomFolderJSONString
    $ParamObj.AddCustomFolder()
}

#Not using direct dll - must install WinSCP module from PSGallery.
#Set-Location $PSScriptRoot
#$dll = (Get-Item -Path ($PSScriptRoot + "\WinSCPnet.dll")).FullName
#$dll = "C:\Users\xxxxx\Downloads\WinSCPnet.dll"
#^^ Copy DLL to a local disk, together with winscp.exe and .ini.
#Not working, because of network share...:
#$dll = "\\server\share\WinSCPnet.dll"
#Write-Host $dll
#$Context.LogMessage($dll, "Information")

$MailLog = [MailLog]::new($MailsmtpServer, $MailRecipients, $MailFrom, $pfSenseMachine)

try {
    $ParamObj.SetWinSCPParams()

    #[Reflection.Assembly]::LoadFrom($dll)

    #Add-Type -Path $dll

    #$sessionOptions = New-Object WinSCP.SessionOptions
    #$sessionOptions.SshPrivateKeyPath = $PrivateKeyPath
    #$sessionOptions.Protocol = [WinSCP.Protocol]::SCP
    #^^ doesn't work with WinSCP newer than 5.5. Get version 5.5x or older to use this.
    #$sessionOptions.Protocol = [WinSCP.Protocol]::SFTP
    #$sessionOptions.HostName = $HostName
    #$sessionOptions.UserName = "pfbackup"
    #$sessionOptions.Password = ""
    #$sessionOptions.SshHostKeyFingerprint = $SshHostKeyFingerprint
    
    # $Credentials = New-Object System.Management.Automation.PSCredential("pfbackup",(New-Object System.Security.SecureString))
    # $SplatWinSCPOptions = @{
    #     SshPrivateKeyPath   = $PrivateKeyPath
    #     HostName            = $HostName 
    #     Protocol            = "Sftp" 
    #     #UserName            = "pfbackup"
    #     Credential          = $Credentials
    #     SshHostKeyFingerprint = $SshHostKeyFingerprint
    # }
    # $sessionOption = New-WinSCPSessionOption @SplatWinSCPOptions

    #$session = New-Object WinSCP.Session

    try {
        # Connect
        #$session.Open($sessionOptions)
        $session = New-WinSCPSession -SessionOption $ParamObj.sessionOptions

        #$session.ListDirectory("/var/custom")

        If (!(Test-Path -Path $ParamObj.BackupLocation -PathType Container)) {
            New-Item -Path $ParamObj.BackupLocation -ItemType Directory
        }

        #Backup custom-folder, if it exist!:
        foreach ($CurrentCustom in $ParamObj.CustomFolders.Keys) {
            $LocalBackupFileName = $null
            If ($ParamObj.CustomFolders[$CurrentCustom].LocalBackupFileName) {
                $LocalBackupFileName = $ParamObj.CustomFolders[$CurrentCustom].LocalBackupFileName
            }
            $RemotePath = $ParamObj.CustomFolders[$CurrentCustom].RemotePath
            $LocalBackupFolder = $ParamObj.CustomFolders[$CurrentCustom].LocalBackupFolder
            $Context.LogMessage("RemotePath: $RemotePath, LocalBackupFolder: $LocalBackupFolder, LocalBackupFileName: $LocalBackupFileName", "Information")

            if (-not $session.FileExists($RemotePath)) {
                $Context.LogMessage("Remote path '$RemotePath' does not exist. Skipping backup for this path.", "Information")
                continue
            }

            try {
                $info = $session.GetFileInfo($RemotePath)
            }
            catch {
                $Context.LogMessage("Failed to get file info for '$RemotePath'. Skipping backup for this path.", "Error")
                $MailLog.AddMessage("[ERROR] Failed to get file info for '$RemotePath'. Skipping backup for this path.")
                continue
            }
            # Check if the remote path is a directory or a file

            if ($info.IsDirectory) {
                # Check if the remote path directory is readable
                try { $session.ListDirectory($RemotePath) }
                catch {
                    Write-Host "Failed to list directory '$RemotePath'. Skipping backup for this path."
                    $MailLog.AddMessage("[ERROR] Failed to list directory '$RemotePath'. Skipping backup for this path.")
                    continue
                }
                $FullLocalPath = $LocalBackupFolder + "\"
                $RemotePath = $RemotePath.TrimEnd("/") + "/"
                # If it's a directory, we can use the LocalBackupFolder as is
            } elseif ($LocalBackupFileName) {
                # If it's a file and LocalBackupFileName is specified, we need to ensure the local path is set correctly
                $FullLocalPath = Join-Path -Path $LocalBackupFolder -ChildPath $LocalBackupFileName
            }

            # Create local backup folder if it doesn't exist
            If (!(Test-Path -Path $LocalBackupFolder -PathType Container)) {
                New-Item -Path $LocalBackupFolder -ItemType Directory
            }
            Set-Location $LocalBackupFolder

            # Download files from remote path to local backup folder
            $transferResult = $session.GetFiles($RemotePath, $FullLocalPath)
            # # Rename file if LocalBackupFileName is specified
            # If ($LocalBackupFileName) {
            #     Rename-Item -Path ($LocalBackupFolder + "\*") -NewName $LocalBackupFileName
            # }
            try {
                $transferResult.Check()
                foreach ($transfer in $transferResult.Transfers) {
                    $MailLog.AddMessage("Download of $($transfer.FileName) succeeded")
                    $Context.LogMessage("Download of $($transfer.FileName) succeeded", "Information")
                }    
            } catch {
                $MailLog.AddMessage("ERROR in download of $($CurrentCustom): $($_.Exception.Message)")
                $Context.LogMessage("ERROR in download of $($CurrentCustom): $($_.Exception.Message)", "Error")
            }
        }

        # Backup config.xml
        Set-Location $ParamObj.BackupLocation
        $FullLocalPath = $ParamObj.BackupLocation + "\" + $("config-" + $ParamObj.pfSenseMachine + "-" + (Get-Date -Format yyyyMMddHHmmss) + ".xml")
        # $transferResultConfig = $session.GetFiles("/cf/conf/config.xml",$($BackupLocation + "\"))
        $transferResult = $session.GetFiles("/cf/conf/config.xml",$FullLocalPath)

        # Rename-Item -Path ($BackupLocation + "\config.xml") -NewName $("config-" + $HostName.ToLower() + "-" + $fileDate + ".xml")

        # Throw on any error
        try {
            $transferResult.Check()
            foreach ($transfer in $transferResult.Transfers) {
                $MailLog.AddMessage("Download of $($transfer.FileName) succeeded")
                $Context.LogMessage("Download of $($transfer.FileName) succeeded", "Information")
            }    
        } catch {
            $MailLog.AddMessage("ERROR in download of /cf/conf/config.xml: $($_.Exception.Message)")
            $Context.LogMessage("ERROR in download of /cf/conf/config.xml: $($_.Exception.Message)", "Error")
        }
        $MailLog.AddMessage("Backup of $pfSenseMachine completed successfully.")
        $Context.LogMessage("Backup of $pfSenseMachine completed successfully.", "Information")
    }
    finally
    {
        # Disconnect, clean up
        $session.Dispose()
    }
#Set-Location $PSScriptRoot
}
catch [Exception] {
    # $MailMessage += $_.Exception.Message
    $MailLog.AddMessage($_.Exception.Message)
    # Write-Error $_.Exception.Message
    $Context.LogMessage($_.Exception.Message, "Error")
    #exit 1
}

$MailLog.SendMail()
$DiscordHook = [DiscordWebHook]::new($DiscordHookUrl, $DiscordThreadId, 
    ("Backup of $pfSenseMachine completed.`r`n`r`n" + $MailLog.GetMailMessage()))
$DiscordHook.Send()

$Context.LogMessage("Sent Mail and Discord - Script finished.", "Information")
