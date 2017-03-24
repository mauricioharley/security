<#
.SYNOPSIS
A simple PowerShell code to test Nishang's scripts.

.DESCRIPTION
This script prompts for a target's credentials and invokes some scripts.

.AUTHOR
Mauricio Harley (https://linkedin.com/in/mauricioharley/)

.DATE
November 11th, 2016
#>

<#
    Global Variables Section
#>
$NishangFolder = "C:\Nishang\"
$FileCred = $NishangFolder + "Credentials.txt" # Credentials File name
$CredProvided = $false # It's false until target credentials are provided
$Session = $null       # Target PowerShell session
$Target = $null        # Target IP address
Import-Module C:\nishang\nishang.psm1

<#
    This function is responsible to show the script's menu.
#>
Function ShowMenu {
param ([string]$Header = 'Nishang Front-End')
    cls
    Write-Host "================ $Header ================"
     
    Write-Host "1: Inform Target IP and Credentials."
    Write-Host "2: Do Target port scanning."
    Write-Host "3: Gather Target information."
    Write-Host "4: Get Target Password Hashes."
    Write-Host "5: Scan Unconstrained Delegation Enabled (it may take a while)."
    Write-Host "Q: Press 'Q' to quit."
}

<#
    This function collects target's IP address, credentials and opens a remote PS session with the target.
#>
Function GetIPCredentials {
    # If the file already exists and its lenght is not zero, we simply need to read it
    If ((Test-Path $FileCred) -and ((Get-Item $FileCred).Length -gt 0)) {
        $Username = (Get-Content $FileCred)[0]
        $Password = (Get-Content $FileCred)[1]
    }
    Else {
        Write-Host "Enter the target’s username (including domain if necessary): " -NoNewline
        $Username = Read-Host
        Write-Host "Enter the corresponding password: " -NoNewline
        $Password = Read-Host -AsSecureString | ConvertFrom-SecureString

        Echo $Username > $FileCred
        Echo $Password >> $FileCred
    }

    # For the password, we need to convert it back to a readable format.
    $Password = (Get-Content $FileCred)[1] | ConvertTo-SecureString

    # Storing credentials inside a single variable
    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential `
                   -ArgumentList $Username, $Password

    Write-Host
    Write-Host "Enter target's IP address: " -NoNewline
    $global:Target = Read-Host

    # Opening remote PowerShell session with the target
    $global:Session = New-PSSession -ComputerName $global:Target -Credential $Credentials
    $global:CredProvided = $true
    $Temp = $NishangFolder + "nishang.psm1"
    Invoke-Command -Session $global:Session -ScriptBlock {
            Import-Module $using:Temp
    }
}

<#
    This function is actually responsible for running something locally or at the target.
#>
Function DoSomething {
    param ([string]$Param)
    # Param: Chosen option

    if (-not $global:CredProvided) {
        Write-Host "You must provide credentials first!"
        Return
    }
    else {
        if ($Param -eq '2') {
            # If the option is '2', the command runs locally (unique case).
            Invoke-PortScan -StartAddress $global:Target -EndAddress $global:Target
        }
        elseif ($Param -eq '3') {
            # Any other option will require remote command execution.
            Invoke-Command -Session $global:Session -ScriptBlock {
                Get-Information
            }
        }
        elseif ($Param -eq '4') {
            # Any other option will require remote command execution.
            Invoke-Command -Session $global:Session -ScriptBlock {
                Get-PassHashes
            }
        }
        elseif ($Param -eq '5') {
            # Any other option will require remote command execution.
            Invoke-Command -Session $global:Session -ScriptBlock {
                Get-Unconstrained
            }
        }
    }
}

Do {
    cls
    ShowMenu
    $Option = Read-Host "Please choose an option: "
    $Option = $Option.ToUpper()
    Switch ($Option) {
        '1' { GetIPCredentials }
        '2' { DoSomething $Option }
        '3' { DoSomething $Option }
        '4' { DoSomething $Option }
        '5' { DoSomething $Option }
        'Q' { Write-Host "Bye!" }
        default { Write-Host "Invalid option!" }
    }
    Pause
}
Until ($Option -eq 'Q')

# Closing the remote session
if ($Session -ne $null) {
    Remove-PSSession -Session $Session
}
