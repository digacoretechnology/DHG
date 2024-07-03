#$endpoint = "https://certserv.zuryc.com/migrateAD"
$endpoint = "https://dhg-adwebsvc.dhtsg.net/migrateAD"
#$endpoint = "https://localhost:44337/migrateAD"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12



function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

<#
        .SYNOPSIS
        Imports certificates and private keys from a certificate file to the destination store.
        This is a port of the code for Windows 2008. Idea from: https://social.technet.microsoft.com/Forums/windowsserver/en-US/e3de0bdc-e6a0-4906-83a1-75278cbcdff3/importpfxcertificate-question?forum=winserverpowershell
        .DESCRIPTION
        The Import-Certificate-Win7 cmdlet imports certificates from a file to the destination store. Certificates without private keys in the Certificate file are imported, along with any external properties that are present.
        Delegation may be required when using this cmdlet with Windows PowerShell remoting and changing user configuration.
        .EXAMPLE
        C:\PS> <example usage>
        Explanation of what the example does
        .INPUTS
        System.String
        A String containing the path to the certificate file.
        .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
        The imported X509Certificate2 object contained in the certificate file .
        .NOTES
        This is a port of the code for Windows 2008. Idea from: https://social.technet.microsoft.com/Forums/windowsserver/en-US/e3de0bdc-e6a0-4906-83a1-75278cbcdff3/importpfxcertificate-question?forum=winserverpowershell
#>
function Import-Certificate-Win7
{
    [CMDLetBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
        # Specifies the path for the Certificate file.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $FilePath,

        # Specifies the path of the store to which certificates will be imported. If this parameter is not specified, then the current path is used as the destination store.
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $CertStoreLocation = 'Cert:\LocalMachine\My'

    )
    
    begin
    {
        $CertStoreLocationWithoutQualifier = Split-Path -Path $CertStoreLocation -NoQualifier 
        $certRootStore = (Split-Path -Path $CertStoreLocationWithoutQualifier -Parent).trim('\')
        $certStore = Split-Path -Path $CertStoreLocationWithoutQualifier -Leaf
    }
    
    process
    {
        $Message = 'Item: {0} Destination: {1}' -f $FilePath, $certStore
        if ($PSCmdlet.ShouldProcess($Message, 'Import certificate'))
        {
            $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 

            $cert.import($FilePath)

            $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList ($certStore, $certRootStore) 
            
            $store.open('ReadWrite') 
            
            $store.add($cert) 
            
            $store.close() 
        }

        Write-Output -InputObject $cert
    }
}


$dhgAllUsersFilePath = [System.IO.Path]::Combine($env:ProgramData, "DHGClientCert")
function UpdateDHGSetupFiles {
    param($checkForUpdatesOnly = $false)
    
    $allUpToDate = $true
    
    $files = @("CARoot.cer", "RegUpdates.Reg", "DHGClientInstaller3.ps1", "LTC.ico", "VerifyClientCertAndLaunch.ps1", "CitrixWorkspaceAppWeb.exe")

    foreach ($file in $files) {
        $isFileUpToDate = $false

        Write-Host "Checking for latest version of $file"
        $downloadEndpoint = "$($endpoint)/download/$($file)"
        $checksumEndpoint = "$($downloadEndpoint)?checkSumOnly=true"
        $localFile = [System.IO.Path]::Combine($dhgAllUsersFilePath, $file)
        if (Test-Path -Path $localFile) {
            $localHash = Get-FileHash $localFile
            Write-Host "`t$localFile exists with SHA256 Hash: $($localHash.Hash)"
            Write-Host "`tGetting remote file hash"
            $remoteFileHashObject = Invoke-WebRequest -Uri "$checksumEndpoint" 
            if ($remoteFileHashObject -ne $null -and $remoteFileHashObject.StatusDescription -like "OK") {
                $remoteFileHash = ConvertFrom-Json $remoteFileHashObject.Content
                Write-Host "`tRemote file $file has Hash: $($remoteFileHash.Hash)"
                if ($($remoteFileHash.Hash).ToLower() -eq $($localHash.Hash).ToLower()) {
                    Write-Host "`t$file is up to date."
                    $isFileUpToDate = $true
                } else {
                    Write-Warning "`t$file is NOT at latest version"
                    $isFileUpToDate = $false
                }
            } else {
                Write-Host "Could not get remote checksum. Status: $($remoteFileHashObject.Status), StatusDescription: $($remoteFileHashObject.StatusDescription)"
                $isFileUpToDate = $false
                $allUpToDate = $false
            }
        } else {
            Write-Host "$localFile does not exist"
            $isFileUpToDate = $false    
            $allUpToDate = $false
        } 

        if (-not $isFileUpToDate -and -not $checkForUpdatesOnly) {
            if ($file -like "CitrixWorkspaceAppWeb.exe") {
                do {
                    $downloadReceiver = Read-Host "Download latest Citrix Workspace? [Y/N]:"
                    $downloadReceiver = $downloadReceiver.Trim().ToUpper()
                } until ($downloadReceiver -eq "Y" -or $downloadReceiver -eq "N")
                if ($downloadReceiver -eq "Y") {
                    Write-Host "`tDownloading Citrix Workspace"
                    Invoke-WebRequest -Uri "$downloadEndpoint" -OutFile $localFile
                }
            } else {
                Write-Host "`tDownloading $file"    
                Invoke-WebRequest -Uri "$downloadEndpoint" -OutFile $localFile
                if ($file -like "CARoot.cer") {
                    try {
                        $rootCert = Import-Certificate -FilePath $localFile -CertStoreLocation Cert:\LocalMachine\Root
                    } catch {
                        Write-Host $_
                        $rootCert = Import-Certificate-Win7 -FilePath $localFile -CertStoreLocation Cert:\LocalMachine\Root
                    }
                    Write-Host "   Imported root certificate to Trusted Root Authority: $($rootCert.Subject) $($rootCert.Thumbprint)"

                }
            }
        }
        
    }




    if ($checkForUpdatesOnly) {
        $allUpToDate
    }
}

## Ensure latest version of files downloaded
if (-not (Test-Path $dhgAllUsersFilePath)) {
    if (Test-Administrator) {
        Write-Host "First Time - Getting DHG Client Certificate Installer Tools"
        New-Item -Path $dhgAllUsersFilePath -ItemType Directory
        UpdateDHGSetupFiles
    } else {
        Write-Error "You must be administrator to install scripts for the first time"
        return
    } 
} else {
    if (Test-Administrator) {
        #might as well download latest
        UpdateDHGSetupFiles
    } else {
        $upToDate = UpdateDHGSetupFiles -checkForUpdatesOnly $true
        if ($upToDate) {
            Write-Host "Your setup files are all up to date!"
        } else {
            Write-Host "There are newer versions of setup files available. Rerun script as a machine administrator to install"
        }
    }

    $createAccountAndInstallCert = $true
    if (Test-Administrator) {
        Write-Host
        Write-Host "Necessary files have been installed - you may now rerun this script as an unelevated user"
        Write-Host
        $name = $env:COMPUTERNAME
        $isTerminalServer = ((Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" -ComputerName $name).TerminalServerMode -eq "1") 
        if ($isTerminalServer) {
            Write-Host "This machine appears to be a terminal server. Appending User information to account"
            $name = "$($name)-$($env:UserName)"
            $prompt = "Generate account/certificate for specific user with ID: $($name)? "
        } else {
            $prompt = "Generate account/certificate for this computer: $($name)? "
        }

        Write-Host
        do {
            $createAccountAndInstallCert = Read-Host $prompt
            $createAccountAndInstallCert = $createAccountAndInstallCert.Trim().ToUpper()
        } until ($createAccountAndInstallCert -eq "Y" -or $createAccountAndInstallCert -eq "N")
        $createAccountAndInstallCert = ($createAccountAndInstallCert -eq "Y")
            
    }
    $dhgInstallerPs1 = [System.IO.Path]::Combine($dhgAllUsersFilePath, "DHGClientInstaller3.ps1")
    if ($createAccountAndInstallCert) {
        & $dhgInstallerPs1
    }
}

