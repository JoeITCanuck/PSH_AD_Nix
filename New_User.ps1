<#
Title:
Synopsis: This script will take your input and create a new user in your network. It creates a user and sets password, assigns it to a primary group and sets UNIX attributes.

INSTRUCTIONS:
1. To use this script, logon to an AD server, in search type Powershell, right click on Powershell-ISE and select to run as administrator.
2. Open this script in another window, copy and paste contents into administrator elevated powershell, or open right from that ISE.
2. Press play button or F5 to start.
3. Answer the questions it prompts you for, optional: go into AD Users and computers and confirm user settings.
3. Send welcome email to new user.

Created by: Joe Pizzacalla
#>

# Powershell environment setup
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
Get-Variable * | Remove-Variable -ErrorAction SilentlyContinue # Removes variables forciby!
Write-Host "$(get-date) Start of script"
$wshell = New-Object -ComObject Wscript.Shell
Clear-Host
Get-Module | Import-Module
$host.ui.RawUI.WindowTitle = "XCompany New User Script 2.0"

#################################################################################################################
# Script Start
# Get Name (From human)
$FirstName = Read-Host  ‘First Name’
$LastName = Read-Host  ‘Last Name’
$FullName = $FirstName + " " + $LastName

# Create User Name (For AD Creation - later)
$Initial =$FirstName.Substring(0,1)
$UserName = ($LastName + "" + $Initial)

# Get Password
$Pass = Read-Host "Password"  # Dumb, but I do this twice and use it in two ways

# Email Function and Array definition
$EmailList = "@Yourdomain.ca", "@CHILDdomain.ca", "@company.itdept.ca"
$EMCount=0
$EMSwitch=0
function Email {
    Write-Host "!!!Email Domain Menu!!!"
    while($EMCount -lt $EmailList.length) {
        Write-host ($EMCount+1)$EmailList[$EMCount]
        $EMCount++
        }
    while($EMSwitch -eq 0) {
        $EmailDomain=$null
        $EMNum= Read-Host 'Choose a # from the menu'
        #Throws an error if non integer is entered, does not break script.
        $EMTNum= $EMNum - 1
        if($EMTNum -lt 0 -or $EMTNum -ge $EmailList.length)
            {
            Write-Host "!!!Number outside of displayed range. Reselect!!!"
            Start-Sleep -Seconds 2
            }else {
            Write-Host "Selection Accepted:" $EmailList[$EMTNum]
            $global:EmailDomain= $EmailList[$EMTNum]
            $EMSwitch++
            }
        }
}

Email
$EmailName= Read-Host 'Email !!e.x jon.doe, domain will be added automatically!!'
$Email = $EmailName + $EmailDomain

# Get Department
# Variables for finding and isolating group names. Sets integers for non-zero list display.
$GROUP=Get-ADGroup -Filter '*' | where-object {$_.distinguishedname -like "*CMN_Teams*"} | select name | sort-object name | ForEach-Object {$_.name} | Out-String -stream | select-object -skip 0
$GCOUNT=$GROUP.length - 1
$LCOUNT=0

#Displays Group list, offsets displayed #s by 1 for eyecandy
function GroupList {
    while($LCOUNT -le $GCOUNT)
        {
        Write-host ($LCOUNT+1)"."$GROUP[$LCOUNT]
       $LCOUNT++
        }
}

$LoopSwitch=0
#Calls Group list function. Accounts for # offset to properly set variable from Array. Error checks. Sets Group variable.
function GrSelect {
    while($LoopSwitch -eq 0) {
        GroupList
        $GSelect=$null
        $CHNum= Read-Host 'Choose a # from the menu'
        #Throws an error if non integer is entered, does not break script. Go to Hell, Remi, loop forever.
        $TRNum= $CHNum - 1
        if($TRNum -lt 0 -or $TRNum -gt $GCOUNT)
            {
            Write-Host "!!!Number outside of displayed range. Reselect!!!"
            Start-Sleep -Seconds 2
            }else {
            Write-Host "Selection Accepted:" $GROUP[$TRNum]
            $global:Department= $GROUP[$TRNum]
            $LoopSwitch++
            }
    }
}

GrSelect

# Get Employee AD info (From Human)
$Title = Read-Host -Prompt 'Employee Title, if known'

#$OfficePhone = Read-Host -Prompt 'Phone (Blank for none) 555-555-5555 format'
#if($OfficePhone = $Null){$OfficePhone = "Format 555-555-5555"}

######################################################################
# Where the magic happens - all info put into new user!
# Prompt for password and place user in Active Directory
    New-ADUser -SamAccountName ($LastName + "" + $Initial) -AccountPassword (Read-Host -AsSecureString "AccountPassword") -DisplayName ($Firstname + " " + $LastName) -CannotChangePassword 0 -ChangePasswordAtLogon 1 -Department $Department -EmailAddress $Email -Enabled 1 -ScriptPath $UserName -Name ($FirstName, $LastName -Join " ") -GivenName $FirstName -Surname $LastName -UserPrincipalName $UserName@Canada.ca -Title $Title #-OfficePhone $OfficePhone

  # Add user to appropriate group membership
    Add-ADGroupMember -Identity $Department -Members $UserName
  # Ads a user to a group you statically assign, something maybe all your users need.
    Add-ADGroupMember -Identity "SAMPLE_Group" $UserName

    # Move user to appropriate OU (To be implemented later)
    #Get-ADUser $UserName | Move-ADObject -TargetPath #"OU=$Department,DC=UNIT,DC=COMPANY,DC=COM"

######################################################################
# UNIX Attributes Editing and Function
# We need to set gidNumber, loginShell, unixHomeDirectory, uid, uidNumber, msSFU30NisDomain

$rc = $?

# Sometimes this seems to timeout, do not set anything if that's the case
If ($rc -ne $True)
{
    write-host "User lookup failed with code $rc, aborting..."
    exit $False
}

# For safety, let's make sure $UserName is actually the user we want ### Needs work
#If ($UserName.sAMAccountName -ne $UserName)
#{
    #write-host "User appears empty, something went wrong"
    #exit $False
#}

# If the msSFU30NisDomain is not set, set it
If ($UserName.msSFU30NisDomain -eq $null)
{
    write-host "Setting domain to XNetwork"
    Set-ADUser -Identity $UserName -Replace @{ msSFU30NisDomain = "XNetwork" }
}

# If the loginShell is not set, set it
If ($UserName.loginShell -eq $null)
{
    write-host "Setting login shell to /bin/bash"
    Set-ADUser -Identity $UserName -Replace @{ loginShell = "/bin/bash" }
}

# If the unixHomeDirectory is not set, set it
If ($UserName.unixHomeDirectory -eq $null)
{
    write-host "Setting homedir domain to /home/$UserName"
    Set-ADUser -Identity $UserName -Replace @{ unixHomeDirectory = "/home/"+"$UserName" }
}

# If the uid is not set, set it
#If ($UserName.uid -eq $null -or [string]$UserName.uid -eq "") REDUNDANT SAFETY STEP, done below. To be removed.
{
    write-host "Setting uid to $($UserName.sAMAccountName)"
    Set-ADUser -Identity $UserName -Replace @{ uid = "$($UserName.sAMAccountName)" }
}

# If the gidNumber is not set, set it
$GID = Get-ADGroup $Department -Properties * | Select gidNumber
If ($UserName.gidNumber -eq $null)
{
    write-host "Setting gidNumber to AD Primary Group"
    Set-ADUser -Identity $UserName -Replace @{ gidNumber = "$($GID.gidNumber)" }
}

# If the uidNumber is not set, set it
If ($user.uidNumber -eq $null)
{
    # Get next available uidNumber
    # Pick a known low starting point
    $low  = 10000
    $high = 18000
    $highestuser = Get-AdUser -Filter { uidNumber -gt $low -and uidNumber -lt $high } -Properties uidNumber | Sort-Object -Property uidNumber -Descending | select-object -first 1
    If ($? -ne $True)
    {
        write-host "Calculating next UID failed on AD lookup, aborting"
        exit
    }
    $nextuid = $highestuser.uidNumber + 1
    write-host "Setting uidNumber to $nextuid"
    Set-ADUser -Identity $UserName -Replace @{ uidNumber = $nextuid }
}

#CONFIRMATION prompts! If no popup, it did not complete...
$wshell.Popup("Verify settings in active directory!",0,"User successfully created. Copy password in from next popup and include in welcome email to user.",0x1)
$wshell.Popup("$pass",0,"Password must be changed upon first login.",0x1)

# Email user to advise of new account
#Send-MailMessage -to $Email -Subject ("XNetwork Account Setup Complete for " + $Firstname + " " + $Lastname) -body ("XNetwork Account setup completed for " + $Firstname + " " + $Lastname + " as a " + $Title +" in the " + $Department + " " + "Department." + "`r`n`n") -smtpserver relay.XNetwork.ssc-spc.gc.ca -from admin@XNetwork.mail

Send-MailMessage -to $Email -Subject ("XNetwork Account Setup Complete for " + $Firstname + " " + $Lastname) -body ("XNetwork Account setup completed for " + $Firstname + " " + $Lastname + ", you will recieve a welcome email and token enrollment email shortly. Follow the instructions in the welcome email to connect to XNetwork." + "`r`n`n") -smtpserver relay.Yourcompany.ca -from admin@yourITdept.ca

<#  Mail Configuration / Info
    From.....................: Your IT Dept
    Address..................: admin@YourITDept.ca
    SMTP Server..............: relay.Yourcompany.ca
    SMTP User Name...........: 
 #>

 Write-Host "$(get-date) End of script"

# Welcome email to sent to new user!
<#
Welcome to XCompany.ca!

Instructions on Connecting to XNetwork:
BLAH SAMPLE TEXT HERE
#>

<# Changelog
V1.0 Early (April) 2018
* Very basic, had initial groups and created accounts, no Unix Attributes set yet.
V1.2~5 Early 2019
* Changes: Added more groups, commented rest of script better
* New: UNIX attributes set dynamically
V1.6 Mid 2019
* Changes: Added more groups
* New: Static default security group automatically included in all new users membership, allowing automatic token enrollment/2FA
V1.7 Jan 2020
* Changes: Added more groups, more commenting of script
* New: Email configuration added, it will now email the user to advise them account has been made and they will receive further instructions.
V1.8 Jan 29 2020
Commented out ViewDesktopUsers line.
Enabled manual Email entry
v1.9 March 12 2020
Modified Group selection function for use in Email domain function.
Email domains can now be specified according to which domains are listed in the domain array called $EmailList
#>