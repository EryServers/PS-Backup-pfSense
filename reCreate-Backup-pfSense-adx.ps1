<#
.SYNOPSIS
    Recreates the Backup-pfSense-adx-script, based on some bad regex.
.DESCRIPTION
    Minimum requirements are: Powershell v5.1.
.EXAMPLE
    .\scriptname.ps1
    Required Parameters.
.NOTES
    Author: Eryniox - 2025
    Date:   June 2025
.LINK
    http://
#>

$InFile = "Backup-pfSense.ps1"
$OutFile = "Backup-pfSense-adx.ps1"
$FullNewScript = ""

$regexRemove = [regex] "(?smi)\s*\[CmdletBinding\(\)\].*#End CmdletBinding"
$regexUncomment = [regex] '(?mi)^(?<lead>\s*)#\s*((?:\[|if).*?Context\.GetParameterValue\(.*?\).*)$'

$CurrentDirectory = $PSScriptRoot
# $CurrentDirectory = (Get-Location).Path
$CurrentFile = Get-Item -Path (Join-Path -Path $CurrentDirectory -ChildPath $InFile)
$OutFullNamePath = Join-Path -Path $CurrentDirectory -ChildPath $OutFile
$Content = $CurrentFile | Get-Content -Raw
# $Content -match $regexRemove
# $Content -match $regexUncomment
# $NewContent -match $regexUncomment
# $Matches
$NewContent = $regexRemove.Replace($Content, "")
# Only remove the # from matching lines, keep everything else unchanged
$NewContent = $regexUncomment.Replace($NewContent, '${lead}$1')

# $NewContent -match [regex]::Escape('[WinSCP.SessionOptions] $sessionOptions = [WinSCP.SessionOptions]::new()')
$NewContent = $NewContent -replace [regex]::Escape('[WinSCP.SessionOptions] $sessionOptions = [WinSCP.SessionOptions]::new()'), '# $0'
$NewContent = $NewContent -replace [regex]::Escape('Send-MailMessage @Params'), '# $0'
# Send-MailMessage @Params
        
# $NewContent -match [regex] ('(?mi)^(?<lead>\s*)#\s*(' + [regex]::Escape('[System.Object] $sessionOptions = (New-WinSCPSessionOption -HostName "temp")') + ')')
# $NewContent -match [regex] ('(?mi)^(?<lead>\s*)#\s*(' + [regex]::Escape('Send-adxMail @Params') + ')')
$NewContent = $NewContent -replace [regex] ('(?mi)^(?<lead>\s*)#\s*(' + [regex]::Escape('[System.Object] $sessionOptions = (New-WinSCPSessionOption -HostName "temp")') + ')'), '${lead}$1'
$NewContent = $NewContent -replace [regex] ('(?mi)^(?<lead>\s*)#\s*(' + [regex]::Escape('Send-adxMail @Params') + ')'), '${lead}$1'
# # Send-adxMail @Params

# [System.Object] $sessionOptions = (New-WinSCPSessionOption -HostName "temp")

# $NewContent | Set-Clipboard


$FullNewScript += $NewContent  # + "`n`n"

Set-Content -Path $OutFullNamePath -Value $FullNewScript -Force
Write-Host "Script finished. New Backup-pfSense-adx should be at: $OutFullNamePath" -ForegroundColor Green
