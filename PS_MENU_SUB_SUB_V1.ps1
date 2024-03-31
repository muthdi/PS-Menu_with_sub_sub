# Check if script is being run as an administrator and relauch as admin if not.
Write-Host "$Strng1 Making sure this script is being run as an Administrator, will respawn if needed. 'n"
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Start-Sleep -s 1
cls
Write-Host "#############################################################"-ForegroundColor green
Write-Host "This script allows you to do most stuff from one place      " -ForegroundColor green
Write-Host "                                                             "-ForegroundColor green
Write-Host "                                                            " -ForegroundColor green
Write-Host "works as designed , without waranty                          "-ForegroundColor green
Write-Host "Version :                    2007-2023       @Dieter Muth    "-ForegroundColor green
Write-Host "##############################################################"-ForegroundColor green
pause
Write-Host ""
Write-Host ""
Write-Host "             script needs to run as administrator            " -ForegroundColor RED
pause
#........................Check permissions
Write-Host "Checking for elevated permissions..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
Write-Host "####WARNING####WARNING#####WARNING#####WARNING#####WARNING####WARNING######WARNING#####WARNING#####WARNING#####WARNING##"-ForegroundColor RED
Write-Host "########################################################################################################################"-ForegroundColor RED
Write-Host "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."-ForegroundColor green
Write-Host "########################################################################################################################"-ForegroundColor RED
Write-Host "####WARNING####WARNING#####WARNING#####WARNING#####WARNING####WARNING######WARNING#####WARNING#####WARNING#####WARNING##"-ForegroundColor RED
pause
exit
}
else {
Write-Host "               Code is running as administrator — go on executing the script...         " -ForegroundColor Green
}
Write-Host "             will clear all variable        " -ForegroundColor Green
pause

# ......................... execution policy
Set-ExecutionPolicy Unrestricted

#.........................Remove Users Variable
        Remove-Variable * -ErrorAction SilentlyContinue

        Clear-Host
        $ErrorActionPreference= 'SilentlyContinue'
        $Error1 = 0
cls
<#........................used Variablen within the script and where
$Computername - 1 -Rename PC local
$wallpaper - 3 Change wallpapern picture
$drive - 4 export your driver
$lockscreen  - 5 Change Lockscreen 
$output - export your settings
$key -  7 get Windows Key 
$featureclienton - 8 install Client features
$featureclientoff - 9 uninstall Client features
$KBArticle - 12  Windows update  install spec KB
$Modulesoffline - 100  install the modules   offline
$Modules - 103  download powershell modules for this script
$stuff  - 104  copy the script , exit this and start from the new folder
$ScriptName - 104  copy the script , exit this and start from the new folder
$mypath  - 104  copy the script , exit this and start from the new folder 
$shortcut  - 104  copy the script , exit this and start from the new folder 
#>



##########################################################################
<#  # ##################################  muster sub & subsub   ############
###...........................subMenu1...............................#
function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    submenu1" -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " main part sub 1"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " main part sub 1"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu1
        if($submenu1 -eq 1){
            subsubMenu1
        }
        # Launch subsubmenu2
        if($submenu1 -eq 2){
            subsubMenu2
        }
    }
}
#............................subsubMenu1 .......................#
function subsubMenu1 {
    $subsubMenu1 = 'X'
    while($subsubMenu1 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    subsubmenu 1" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " main part sub  sub 1"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " main part sub  sub 1"
        $subsubMenu1 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu1 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 1'
            pause
        }
        # Option 2
        if($subsubMenu1 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 1'
            pause
        }

    }
}
#................................. subsubMenu2 ..............................#
function subsubMenu2 {
    $subsubMenu2 = 'X'
    while($subsubMenu2 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    subsubmenu 2" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " main part sub  sub 2"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " main part sub  sub 2"
        $subsubMenu2 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu2 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 2'
            pause
        }
        # Option 2
        if($subsubMenu2 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 2'
            pause
        }

    }
}
##############################
#>



mode 300
#########################################################################################
# ..............................................................................MAIN MENU
#########################################################################################
function mainMenu {
    $mainMenu = 'X'
    while($mainMenu -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "    home of stuff " -ForegroundColor magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor green  " !!!!!  you need to install modules ( point 100 extended  ) for this script !!!!!"
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white "  system "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow "  Hyper-V"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white "  Tools"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow "  Network"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white "  Active Directory"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow "  Endpoint Management"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white "  Exchange"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow "  Office 365"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white "  Remoting"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " VMWARE "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Lab "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Everything with MDT"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows Client"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Windows Server"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Linux Client"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "16"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Linux Server"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "98"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Powershell tools"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "99"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Fun"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "100"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor green " for this script "


        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch submenu1
        if($mainMenu -eq 1){
            subMenu1
        }
        # Launch submenu2
        if($mainMenu -eq 2){
            subMenu2
        }
        # Launch submenu3
        if($mainMenu -eq 3){
            subMenu3
        }
        # Launch submenu4
        if($mainMenu -eq 4){
            subMenu4
        }
        # Launch submenu5
        if($mainMenu -eq 5){
            subMenu5
        }
        # Launch submenu6
        if($mainMenu -eq 6){
            subMenu6
        }
        # Launch submenu7
        if($mainMenu -eq 7){
            subMenu7
        }
        # Launch submenu8
        if($mainMenu -eq 8){
            subMenu8
        }
        # Launch submenu9
        if($mainMenu -eq 9){
            subMenu9
        }
        # Launch submenu10
        if($mainMenu -eq 10){
            subMenu10
        }
        # Launch submenu11
        if($mainMenu -eq 11){
            subMenu11
        }
        # Launch submenu12
        if($mainMenu -eq 12){
            subMenu12
        }
        # Launch submenu13
        if($mainMenu -eq 13){
            subMenu13
        }
        # Launch submenu14
        if($mainMenu -eq 14){
            subMenu14
        }
        # Launch submenu15
        if($mainMenu -eq 15){
            subMenu15
        }
        # Launch submenu16
        if($mainMenu -eq 16){
            subMenu16
        }
        # Launch submenu98
        if($mainMenu -eq 98){
            subMenu98
        }
        # Launch submenu99
        if($mainMenu -eq 99){
            subMenu99
        }
        # Launch submenu100
        if($mainMenu -eq 100){
            subMenu100
        }
    }
}
#................................ system subMenu1 ................................#
function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of system  " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basics"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu1
        if($submenu1 -eq 1){
            subsubMenu1
        }
        # Launch subsubmenu2
        if($submenu1 -eq 2){
            subsubMenu2
        }
    }
}
#............................. system  subsubMenu1 ...........................................#
function subsubMenu1 {
    $subsubMenu1 = 'X'
    while($subsubMenu1 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of systems basic " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " rename pc"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " enable remote desktop"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " change wallpaper"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " change lockscreen"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white  " get your windows key"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " enable-PSRemoting"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " enable WSMan local for all"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " test WSMan"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows update  check"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Windows update  install"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows update  install spec KB"

        $subsubMenu1 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu1 -eq 1){
        ### 1 rename pc 
        cls 
        Write-Host "#####################################################################" -ForegroundColor Green  
        Write-Host "#      will change the computername LOCAL to xxx and restart        #"  -ForegroundColor Green 
        Write-Host "#                                                                   #"  -ForegroundColor Green 
        Write-Host "#                works as designed - no warranty                    #"  -ForegroundColor Green 
        Write-Host "#                       design : dieter muth                        #" -ForegroundColor Green 
        Write-Host "#                     version : V 1.0  /2007 - 2023                 #" -ForegroundColor Green  
        Write-Host "#####################################################################" -ForegroundColor Green 
       	pause
	    CLS
        Write-Host "#################################################################################################"
        Write-Host "                                READ ABOUT allowed signs                                        " -foregroundcolor red
        Write-Host "            All alphanumeric ASCII characters (letters A-Z and numbers 0-9)                     "
        Write-Host "you can’t have a NetBIOS name that only contains number (e.g. 1234567) due to a DNS restriction."
        Write-Host "Although underscore (_)can be used in a NetBIOS name, it’s not allowed in a DNS hostname so your computer will fail to communicate on the Internet"
        Write-Host "Although hyphen (-) is allowed in a NetBIOS name"
        Write-Host "Disallowed Characters in NetBIOS Names :  \ / . * ? < > | , ~ : ! @ # $ % ^ & ( ) { } _ space )"
        Write-Host "###############################################################################################"
        pause
		Write-Host ""
        write-Host "                    you get it ? let`s start                   " -foregroundcolor green 
		Write-Host "            the computer will restart !!!!! -  think           " -foregroundcolor red 
		Write-Host ""
        Write-Host "current hostname " -foregroundcolor green 
        $env:computername
        # PartOfDomain (boolean Property)
        Write-Host "domain/workgroup ??????" -foregroundcolor green 
                (Get-WmiObject -Class Wiass Win32_ComputerSystem).PartOfDomain

        # Workgroup (string Property)
                (Get-WmiObject -Class Win32_ComputerSystem).Workgroup

        Write-Host ""
        $Computername = Read-Host "          what name the host schould be changed too       " 
               
        Rename-Computer -NewName "$Computername" -Restart -Force
        }
        # Option 2
        if($subsubMenu1 -eq 2){
        ### 2 Cenable remote desktop 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       enable remote desktop      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green 
        pause
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
        Enable-PSRemoting
        (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName "$env:computername" -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
        Enable-NetFirewallRule -DisplayGroup "RemoteDesktop"
        write-host ""
        Write-Host "                      done  for                 "  -foregroundcolor green
        write-host "                      computer " "$env:computername"
        pause
        }

        # Option 3
        if($subsubMenu1 -eq 3){
        ### 3 Change wallpaper
        cls 
        Write-Host "#######################################################" -ForegroundColor Green  
        Write-Host "#    will change the Wallpaperpicture for all user    #"  -ForegroundColor Green 
        Write-Host "#                                                     #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty                     #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth                           #" -ForegroundColor Green 
        Write-Host "#    version : V 1.0  /2007 - 2023                    #" -ForegroundColor Green  
        Write-Host "#######################################################" -ForegroundColor Green 
        pause
        cls
        Write-Host "           Select the source folder and the picture            "

        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $false # Multiple files can be chosen
	    Filter = 'Images (*.jpg, *.png)|*.jpg;*.png' # Specified file types
            }
         [void]$FileBrowser.ShowDialog()
         $wallpaper = $FileBrowser.FileName;

        If($FileBrowser.FileNames -like "*\*") {

        # Do something 
	    $FileBrowser.FileName #Lists selected files (optional)
	            }

        else {
         Write-Host "Cancelled by user"
                    }
          
        Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper -value "$wallpaper"
        Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper -value "0"
        Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "10" -Force
        write-Host ""
        Write-Host "           after logoff and logon again you see           "-ForegroundColor Green 
        write-Host ""
         pause 
            # Pause and wait for input before going back to the menu
            #Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            #Write-Host "`nPress any key to return to the previous menu"
            #[void][System.Console]::ReadKey($true)
        }


        # Option 4
        if($subsubMenu1 -eq 4){
        ### 4 Change Lockscreen 
        cls 
        Write-Host "###################################################" -ForegroundColor Green  
        Write-Host "# will change the LOCKSCREEN picture for all user #"  -ForegroundColor Green 
        Write-Host "#                                                 #"  -ForegroundColor Green 
        Write-Host "#          works as designed - no warranty        #"  -ForegroundColor Green 
        Write-Host "#                 design : dieter muth            #" -ForegroundColor Green 
        Write-Host "#           version : V 1.0  /2007 - 2023         #" -ForegroundColor Green  
        Write-Host "###################################################" -ForegroundColor Green 
        pause
        cls
        Write-Host "                 Select the source folder and the picture               "  -foregroundcolor green

        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $false # Multiple files can be chosen
	    Filter = 'Images (*.jpg, *.png)|*.jpg;*.png' # Specified file types
            }
         [void]$FileBrowser.ShowDialog()
         $lockscreen = $FileBrowser.FileName;

        If($FileBrowser.FileNames -like "*\*") {

        # Do something 
	    $FileBrowser.FileName #Lists selected files (optional)
	            }

        else {
         Write-Host "Cancelled by user"
                    }        
        $regKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
        # create the key if it doesn't already exist
        if (!(Test-Path -Path $regKey)) {
        $null = New-Item -Path $regKey
          }
        # now set the registry entry
        Set-ItemProperty -Path $regKey -Name LockScreenImage -value "$lockscreen"
        Write-Host " "         
        Write-Host "                 Lockscreen is set - after reboot you will see            "  -foregroundcolor green
        Write-Host " " 
        pause
        }


        # Option 5
        if($subsubMenu1 -eq 5){
        ### 5 get Windows Key
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       get Windows Key            #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
        pause
        cls
        write-host""
        $key=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -name BackupProductKeyDefault
        write-host "$key"
        Get-ComputerInfo | select WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
        wmic path softwarelicensingservice get OA3xOriginalProductKey
                Write-Host "                      done                   "  -foregroundcolor green
        pause
        }

        # Option 6
        if($subsubMenu1 -eq 6){
        ### 6  Enable-PSRemoting 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        Enable-PSRemoting         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
        Enable-PSRemoting
        Write-Host "#             done                     #"  -ForegroundColor Green
        pause
        }

        # Option 7
        if($subsubMenu1 -eq 7){
        ### 7 enable WSMan local for all 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#    enable WSMan local for all    #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
	    pause
        Set-Item wsman:\localhost\client\trustedhosts *
        Restart-Service WinRM

        }

        # Option 8
        if($subsubMenu1 -eq 8){
        ###  8 Test WSMan 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#          Test WSMan              #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
		pause
        $Computer = Read-Host -Prompt 'put in name or IP'
        Test-WsMan  -ComputerName "$Computer"
        pause
        }

        # Option9
        if($subsubMenu1 -eq 9){
        ### 9 windows update check
        cls
        Write-Host "####################################" -ForegroundColor Green 
        Write-Host "#       Windows update check       #"  -ForegroundColor Green
        Write-Host "#                                  #"  -ForegroundColor Green
        Write-Host "#      will take some minutes      #"  -ForegroundColor Green
        Write-Host "####################################" -ForegroundColor Green
        pause
        Get-WindowsUpdate
        pause
        }

        # Option 10
        if($subsubMenu1 -eq 10){
        ### 10  Install-WindowsUpdate 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      Install-WindowsUpdate       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
		pause
        cls
        If (-not(Get-InstalledModule PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Write-Host "Module does not exist  ---  go and install / download  "
        }
        Else {
        Write-Host "Module exists"
        }
        cls
        Write-Host "#####################################" -ForegroundColor Green 
        Write-Host "# Windows update install and reboot #"  -ForegroundColor Green
        Write-Host "#                                   #"  -ForegroundColor Green
        Write-Host "#      will take some minutes       #"  -ForegroundColor Green
        Write-Host "#####################################" -ForegroundColor Green
        pause

        Get-WindowsUpdate - -AcceptAll -ForceInstall -AutoReboot

        }

        # Option 11
        if($subsubMenu1 -eq 11){
        ### 11  Windows update  install spec KB 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "# Windows update  install spec KB  #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        If (-not(Get-InstalledModule PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Write-Host "Module does not exist  ---  go and install / download  "
        }
        Else {
        Write-Host "Module exists"
        }
        cls
        Write-Host "####################################" -ForegroundColor Green 
        Write-Host "#    Windows install spec KB       #"  -ForegroundColor Green
        Write-Host "####################################" -ForegroundColor Green
        $KBArticle = Read-Host -Prompt 'put in KBArticle  - KBxxxxx'
        cls
        Get-WindowsUpdate -Install -KBArticleID '$KBArticle'
        pause
 
        }

    }
}
#............................... systems subsubMenu2 .............................................#
function subsubMenu2 {
    $subsubMenu2 = 'X'
    while($subsubMenu2 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of systems extended " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " export your driver"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " export your settings"        
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " turn Windows feature on"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " turn Windows feature off"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows update  check"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " indows update  install"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " indows update  install spec KB"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " list all scheduled tasks"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " list scheduled tasks  select status"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " list scheduled tasks select Name"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "11"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " list restore point"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "12"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " create restore point"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "13"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " enable restore point"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "14"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " make backup "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "15"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " List all details of backup "

        $subsubMenu2 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu2 -eq 1){
        ### 1 export your driver  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       export your driver         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green 
        pause 
        cls 
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#       select your output folder     #"-ForegroundColor Green 
        write-Host "#######################################"-ForegroundColor Green 

        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder containing the reports'
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $drive = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        Export-WindowsDriver -Online -Destination $drive
        Write-Host "                      done                   "  -foregroundcolor green
        pause

        }
        # Option 2
        if($subsubMenu2 -eq 2){
        ### 2 export your settings 
        cls
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#    export your settings for :       #"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
        pause
        cls
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#    select your output folder        #"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder containing the reports'
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $output = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }
        # Write-Host "                      done                   "  -foregroundcolor green
        # pause
        }
        # Option 3
        if($subsubMenu2 -eq 3){
        ### 3 install Client features 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#    install Client features       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Write-Host "                      go on and remember the feature name you want to install                     "  -foregroundcolor green
        Write-Host "                                 remember there are subfeature tools                              "  -foregroundcolor green
        Write-Host "                      some feature can be installed with ManagementTools                          "  -foregroundcolor green
        Write-Host "if you need them  type in the next step additional to the name : xxx --IncludeAllSubFeature -IncludeManagementTools  "  -foregroundcolor green
        pause
        cls
        # show feature
        Get-WindowsOptionalFeature -online |Out-Host –Paging #List all features and status
        $featureclienton = Read-Host  "              give me the name of the feature   ex.: UpdateServices                    "

        Enable-WindowsOptionalFeature -online -FeatureName "$featureclienton" -All  
 
        Write-Host "           we are done  - you ned to restart                    "  -foregroundcolor green              
        pause
        }
        # Option 4
        if($subsubMenu2 -eq 4){
        ### 4 uninstall Client features 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#    uninstall Client features     #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Write-Host "                      go on and remember the feature name you want to uninstall                   "  -foregroundcolor green
        Write-Host "                                 remember there are subfeature tools                              "  -foregroundcolor green
        Write-Host "                      some feature can be installed with ManagementTools                          "  -foregroundcolor green
        Write-Host "if you need them  type in the next step additional to the name : xxx --IncludeAllSubFeature -IncludeManagementTools  "  -foregroundcolor green
        pause
        cls
        # show feature
        Get-WindowsOptionalFeature -online |Out-Host –Paging #List all features and status
        $featureclientoff = Read-Host  "              give me the name of the feature   ex.: UpdateServices                    "

        disable-WindowsOptionalFeature -online -FeatureName "$featureclientoff"  
 
        Write-Host "           we are done  - you ned to restart                    "  -foregroundcolor green             
        pause
        }
        # Option 5
        if($subsubMenu2 -eq 5){
        ### 5 Windows update check
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      Windows update check        #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        If (-not(Get-InstalledModule PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Write-Host "Module does not exist  ---  go and install / download  "
        pause
        }
        Else {
        Write-Host "Module exists"
        }
        cls
        Write-Host "####################################" -ForegroundColor Green 
        Write-Host "#       Windows update check       #"  -ForegroundColor Green
        Write-Host "#                                  #"  -ForegroundColor Green
        Write-Host "#      will take some minutes      #"  -ForegroundColor Green
        Write-Host "####################################" -ForegroundColor Green
        pause
        cls
        Get-WindowsUpdate
        pause
        }
        # Option 6
        if($subsubMenu2 -eq 6){
        ### 6  Install-WindowsUpdate 
                cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      Install-WindowsUpdate       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        If (-not(Get-InstalledModule PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Write-Host "Module does not exist  ---  go and install / download  "
        }
        Else {
        Write-Host "Module exists"
        }
        cls
        Write-Host "#####################################" -ForegroundColor Green 
        Write-Host "# Windows update install and reboot #"  -ForegroundColor Green
        Write-Host "#                                   #"  -ForegroundColor Green
        Write-Host "#      will take some minutes       #"  -ForegroundColor Green
         Write-Host "#####################################" -ForegroundColor Green
        pause
        cls
        Get-WindowsUpdate - -AcceptAll -ForceInstall -AutoReboot
            }
        # Option 7
        if($subsubMenu7 -eq 7){
        ### 7  Windows update  install spec KB 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "# Windows update  install spec KB  #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        If (-not(Get-InstalledModule PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Write-Host "Module does not exist  ---  go and install / download  "
        }
        Else {
        Write-Host "Module exists"
        }
        cls
        Write-Host "####################################" -ForegroundColor Green 
        Write-Host "#    Windows install spec KB       #"  -ForegroundColor Green
        Write-Host "####################################" -ForegroundColor Green
        $KBArticle = Read-Host -Prompt 'put in KBArticle  - KBxxxxx'
        cls
        Get-WindowsUpdate -Install -KBArticleID '$KBArticle'
        pause
        }
        # Option 8
        if($subsubMenu2 -eq 8){
        ### 8  list scheduled tasks 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       list scheduled tasks       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Get-ScheduledTask |Out-GridView
         }
        # Option 9
        if($subsubMenu2 -eq 9){
        ###  9 list scheduled tasks  select status 
        cls 
        Write-Host "#######################################" -ForegroundColor Green  
        Write-Host "# list scheduled tasks  select status #"  -ForegroundColor Green 
        Write-Host "#                                     #"  -ForegroundColor Green 
        Write-Host "#    works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#         design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#     version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "#######################################" -ForegroundColor Green
			pause
			cls
        $State = Read-Host -Prompt 'put in your selection ( ready or disabled  - no input will execute) '
        Get-ScheduledTask | where state -eq "$State" |Out-Host –Paging
        }
        # Option 10
        if($subsubMenu2 -eq 10){
        ### 10  list scheduled tasks  select Name 
        cls 
        Write-Host "################################################" -ForegroundColor Green 
        Write-Host "# list all scheduled tasks with select by name #"  -ForegroundColor Green
        Write-Host "#                                              #"  -ForegroundColor Green
        Write-Host "#        works as designed - no warranty       #"  -ForegroundColor Green 
        Write-Host "#             design : dieter muth             #" -ForegroundColor Green 
        Write-Host "#         version : V 1.0  /2007 - 2023        #" -ForegroundColor Green  
        Write-Host "################################################" -ForegroundColor Green
			pause
			cls

        $Taskname = Read-Host -Prompt 'put in Name  '
        Get-ScheduledTask -taskname  "$Taskname*"
        pause
        }           
        # Option 11
        if($subsubMenu2 -eq 11){
        ###  11   get restore point 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        get restore point         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Get-ComputerRestorePoint |Out-GridView
        }
        # Option 12
        if($subsubMenu2 -eq 12){
        ###  12  create restore point 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        create restore point      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
		pause
		cls
        $restdescripion = read-host - "give me Description of your restore point : "
        $resttype = read-host - "give me Type of your restore point ( possible: APPLICATION_INSTALL;APPLICATION_UNINSTALL;CANCELLED_OPERATION;DEVICE_DRIVER_INSTALL;MODIFY_SETTINGS "
        Checkpoint-Computer -Description "$restdescripion" -RestorePointType "$resttype"
         }
        # Option 13
        if($subsubMenu2 -eq 13){
        ###  13   enable restore point  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       enable restore point       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        $restenable = Read-Host - " give me drive to enable restore point ( ex C:,d: ) "
        Enable-ComputerRestore -Drive "$restenable"
        }
        # Option 14
        if($subsubMenu2 -eq 14){
        ###  14   create backup   
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      create backup from C:       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
		pause
		cls
        Write-Host""
        Write-Host""
        $backup = read-host - "  your backup drive ( ex :  I: ) "
        wbAdmin start backup -backupTarget:"$backup" -include:C: -allCritical

        WBAdmin get versions |Out-GridView
         }
        # Option 15
        if($subsubMenu2 -eq 15){
        ###  15  List all details of backup     
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#  List all details of backup      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
		pause
		cls
        WBAdmin get versions |Out-GridView 
        Write-Host "###########################################################" -ForegroundColor Magenta  
        Write-Host "#  to delete Backups with powershell /cmd use             #"  -ForegroundColor Magenta
        Write-Host "#  WBAdmin Enable Backup                                  #"  -ForegroundColor Magenta 
        Write-Host "# WBADMIN DELETE BACKUP -version:03/31/2006-10:00         #"  -ForegroundColor Magenta 
        Write-Host "# WBADMIN DELETE BACKUP -keepVersions:3                   #" -ForegroundColor Magenta 
        Write-Host "# WBADMIN DELETE BACKUP -backupTarget:f: -deleteOldest    #" -ForegroundColor Magenta  
        Write-Host "###########################################################" -ForegroundColor Magenta
        Write-Host "#          to generate a scheduled Backup use             #"  -ForegroundColor Magenta
        Write-Host "#  WBAdmin Enable Backup                                  #"  -ForegroundColor Magenta 
        Write-Host "###########################################################" -ForegroundColor Magenta
        }
        # Option 16
        if($subsubMenu2 -eq 16){
        ##  put your code here
            Write-Host ' n.n.'
            pause
        }

    }
}
#.............................. hyper-v subMenu2 .........................................#
function subMenu2 {
    $subMenu2 = 'X'
    while($subMenu2 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of hyper-v " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended "
        $subMenu2 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu3
        if($submenu2 -eq 1){
            subsubMenu3
        }
        # Launch subsubmenu4
        if($submenu2 -eq 2){
            subsubMenu4
        }
    }
}
#............................... hyper-v  subsubMenu3 ......................................#
function subsubMenu3 {
    $subsubMenu3 = 'X'
    while($subsubMenu3 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    hyper-v sub3" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " list switch "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " create Hyper_V Switch"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " delete switch"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " list VM"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " list Information about VM"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " create Hyper_V Client V1"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " create Hyper_V Client V2"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " delete VM "

        $subsubMenu3 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu3 -eq 1){
        ###  1   list switch
        cls 
        Write-Host "##########################################" -ForegroundColor Green  
        Write-Host "#        List Hyper -V Switch            #"  -ForegroundColor Green 
        Write-Host "#                                        #"  -ForegroundColor Green 
        Write-Host "#     works as designed - no warranty    #"  -ForegroundColor Green 
        Write-Host "#            design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#     version : V 1.0  /2007 - 2023      #" -ForegroundColor Green  
        Write-Host "##########################################" -ForegroundColor Green
			pause
        get-vmswitch | select Name,SwitchType,AllowManagementOS   |Out-GridView -Title VMSwitch
        }
        # Option 2
        if($subsubMenu3 -eq 2){
        ###  2 create Hyper_V Switch 
        cls
        Write-Host "######################################" -ForegroundColor Green 
        Write-Host "# make your basic switchs on Hyper-V #"  -ForegroundColor Green
        Write-Host "#                                    #"  -ForegroundColor Green
        Write-Host "# works as designed - no warranty    #"  -ForegroundColor Green
        Write-Host "#      design : dieter muth          #" -ForegroundColor Green
        Write-Host "#  version : V 1.0  /2007 - 2023     #" -ForegroundColor Green 
        Write-Host "######################################" -ForegroundColor Green
        pause
        cls
        Write-Host "######################################" -ForegroundColor Green
        Write-Host "#      List  of your switches        #"-ForegroundColor Green
        Write-Host "######################################" -ForegroundColor Green
        
        Get-VMSwitch |Format-List name , SwitchType
                pause
               
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#  List  of your Network Adapters        #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green

        $NIC ="Ethernet*"
        Get-NetAdapter -name $nic | Format-List Name,`
        InterfaceDescription, DeviceName,LinkSpeed ,Status

        pause
        cls
        Write-Host "#####################################################"-ForegroundColor Green
        Write-Host "#####################################################"-ForegroundColor Green
        Write-Host "#             put in name of the switch             #"-ForegroundColor Green
        Write-Host "#####################################################"-ForegroundColor Green
        Write-Host "#####################################################"-ForegroundColor Green
        $switchname = Read-Host -Prompt 'switch name'
        cls
        Write-Host "#####################################################"-ForegroundColor Green
        Write-Host "#####################################################"-ForegroundColor Green
        Write-Host "# put in Type ( privat/internal/external )          #"-ForegroundColor Green
        Write-Host "#####################################################"-ForegroundColor Green
        Write-Host "#####################################################"-ForegroundColor Green
        $switchType = Read-Host -Prompt 'switch name'

        # Create Hyper-V Switch
        Write-host "Creating  virtual switch..."
        New-VMSwitch -Name "$switchname" -SwitchType "$switchType" | Out-Null
        Start-Sleep -Seconds 10
        Write-host " virtual switch created" -ForegroundColor Green
        }
        # Option 3
        if($subsubMenu3 -eq 3){
         ###  3   delte switch
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#         delete switch            #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        }

        # Option 4
        if($subsubMenu3 -eq 4){
        ###  4 list VM
        cls 
        Write-Host "##########################################" -ForegroundColor Green  
        Write-Host "#        List Hyper - V machines         #"  -ForegroundColor Green 
        Write-Host "#                                        #"  -ForegroundColor Green 
        Write-Host "#     works as designed - no warranty    #"  -ForegroundColor Green 
        Write-Host "#            design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#     version : V 1.0  /2007 - 2023      #" -ForegroundColor Green  
        Write-Host "##########################################" -ForegroundColor Green
			pause
        Get-VM |Out-GridView
        }
        # Option 5
        if($subsubMenu3 -eq 5){
         ###  5 information about VM
        cls 
        Write-Host "##########################################" -ForegroundColor Green  
        Write-Host "#    Information about a Hyper-V machine #"  -ForegroundColor Green 
        Write-Host "#                                        #"  -ForegroundColor Green 
        Write-Host "#     works as designed - no warranty    #"  -ForegroundColor Green 
        Write-Host "#            design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#     version : V 1.0  /2007 - 2023      #" -ForegroundColor Green  
        Write-Host "##########################################" -ForegroundColor Green
			pause
        $VMname = Read-Host -Prompt 'put in VM Name' 
        Get-VM -Name "$VMname" | select-object VMName,Path,Uptime,Generation,ProcessorCount,DynamicMemoryEnabled,CreationTime,IsClustered | Out-GridView
        }
        # Option 6
        if($subsubMenu3 -eq 6){
        ### 6 make your VM  Gen1 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       make your VM  Gen1         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        }
        # Option 7
        if($subsubMenu3 -eq 7){
        ### 7 make your VM  Gen2 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       make your VM  Gen2         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause

        }
        # Option 8
        if($subsubMenu3 -eq 8){
        ###  8 
        cls 
        Write-Host "##########################################" -ForegroundColor Green  
        Write-Host "#                 delete vm              #" -ForegroundColor Green 
        Write-Host "#                                        #"  -ForegroundColor Green 
        Write-Host "#     works as designed - no warranty    #"  -ForegroundColor Green 
        Write-Host "#            design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#     version : V 1.0  /2007 - 2023      #" -ForegroundColor Green  
        Write-Host "##########################################" -ForegroundColor Green
			pause
        $VMname = Read-Host -Prompt 'put in VM Name' 
 
        }

    }
}
#............................ hyper-v subsubMenu4 ......................................#
function subsubMenu4 {
    $subsubMenu4 = 'X'
    while($subsubMenu4 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    hyper sub4 " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " backup Hyper-V Client"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " restore Hyper-V Client"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " move VM to other disk"
        $subsubMenu4 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu4 -eq 1){
        ###  1  backup Hyper-V Client  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#     backup Hyper-V Client        #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        }
        # Option 2
        if($subsubMenu4 -eq 2){
        ###  2 restore Hyper-V Client 
        cls 
        Write-Host "##########################################" -ForegroundColor Green  
        Write-Host "# restore Hyper-V Client Hyper-V Client  #"  -ForegroundColor Green 
        Write-Host "#                                        #"  -ForegroundColor Green 
        Write-Host "#     works as designed - no warranty    #"  -ForegroundColor Green 
        Write-Host "#            design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#     version : V 1.0  /2007 - 2023      #" -ForegroundColor Green  
        Write-Host "##########################################" -ForegroundColor Green
			pause
        }
        # Option 3
        if($subsubMenu4 -eq 3){
        ### 3 move VM to other disk 
               cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#     Move VM to another disk      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        # Move VM to another disk
        # select new Path

        Write-Host "########################################"-ForegroundColor Green 
        Write-Host "#select your new folder / remember Name#"-ForegroundColor Green 
        write-Host "#######################################"-ForegroundColor Green 

        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder containing the reports'
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $newFolder = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }
        ""
        ""
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#            see your VM`s            #"-ForegroundColor Green 
        write-Host "#######################################"-ForegroundColor Green 
 
        Get-VMHardDiskDrive -VMName * |select VMNAME,path |Out-Host –Paging


        $VM = Read-Host "          what VM schould  moved      " 
        $oldfolder = Get-VMHardDiskDrive -VMName "$VM" |select path
                Move-VMStorage $VM -DestinationStoragePath "$newFolder"

        write-host "# remember  ---   clean old path #"

        pause  
        }

    }
}
#...........................tools subMenu3...............................#
function subMenu3 {
    $subMenu3 = 'X'
    while($subMenu3 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of tools " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended"
        $subMenu3 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu5
        if($submenu3 -eq 1){
            subsubMenu5
        }
        # Launch subsubmenu6
        if($submenu3 -eq 2){
            subsubMenu6
        }
    }
}
#...........................tools subsubMenu5 .......................#
function subsubMenu5 {
    $subsubMenu5 = 'X'
    while($subsubMenu5 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    tools subsubmenu 1" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " open remote desktop "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " shut down computer from list"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " wakes up computers from list"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " count files and folders"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " ZIP the staff you want"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Copy the stuff you need with robocopy"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " List files and folder"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " List empty directories"
        $subsubMenu5 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu5 -eq 1){
        ###  1  run mstsc 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#         run mstsc                #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        mstsc /f
        }
        # Option 2
        if($subsubMenu5 -eq 2){
         ###  2  shut down computer from list 
               cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#   shut down computer from list   #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls

        Write-Host "           Select the list            "

        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $false # Multiple files can be chosen
	    Filter = 'files (*.csv, *.txt)|*.csv;*.txt' # Specified file types
            }
         [void]$FileBrowser.ShowDialog()
         $shutdown = $FileBrowser.FileName;

        If($FileBrowser.FileNames -like "*\*") {

        # Do something 
	    $FileBrowser.FileName #Lists selected files (optional)
	            }

        else {
         Write-Host "Cancelled by user"
                    }


        $Computers = gc "$shutdown"
        foreach($Computer in $Computers){shutdown /m "\\${Computer}" /s /t 0 /f}
        }
        # Option 3
        if($subsubMenu5 -eq 3){
         ### 3   wakes up a computer from list" 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#   wakes up a computer from list  #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        }
        # Option 4
        if($subsubMenu5 -eq 4){
        ### 4 count files and folders 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#     count files and folders      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#           select the  folder        #"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
        
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $count = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }
        Get-ChildItem D:\ -Recurse | Measure-Object | %{$_.Count}
        #cd $count 
        #(Get-ChildItem -Recurse | Measure-Object).Count | Out-File -FilePath c:\temp\count.txt
        #(Get-Child# -Directory -Recurse | Measure-Object).Count
        #(Get-ChildItem -File -Recurse | Measure-Object).Count
        #Write-Host ""
        #Write-Host "     done find result in C:\temp\count.txt             "  -foregroundcolor green
        pause
        }
        # Option 5
        if($subsubMenu5 -eq 5){
        ###  5  ZIP the stuff you want 
               cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       ZIP the stuff you want     #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# you need to have 7-zip installed #"  -ForegroundColor red
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Write-Host "# select your sourceZIP folder #"-ForegroundColor Green
        
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $sourceZIP = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }
                Write-Host "# select your target folder #"-ForegroundColor Green
        
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $targetZIP = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        & "C:\Program Files\7-Zip\7z.exe" -mx=5 a -tzip -bd $targetZIP.zip  $sourceZIP -r  

         Write-Host "                      we are done                    "  -foregroundcolor green             
         pause
        }
        # Option 6
        if($subsubMenu5 -eq 6){
        ### 6 copy Stuff you need 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      copy Stuff you need         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        If (-not(Get-InstalledModule RobocopyPS -ErrorAction silentlycontinue)) {
        Write-Host "Module does not exist  ---  go and install / download  "
        }
        Else {
        Write-Host "Module exists"
        }
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "# copy your stuff with robocopy       #"-ForegroundColor Green 
        Write-Host "#######################################"-ForegroundColor Green 
               pause
        Write-Host "# select your source folder #"-ForegroundColor Green
        
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $sourcefolder = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }
                Write-Host "# select your target folder #"-ForegroundColor Green
        
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $targetfolder = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }


        Copy-RoboItem -Source "$sourcefolder" -Destination "$targetfolder" -IncludeEmptySubDirectories -Force
         
         Write-Host "                      we are done                    "  -foregroundcolor green             
         pause
         }
         # Option 7
        if($subsubMenu5 -eq 7){
        ###  7  List files and folders  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      List files and folders      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Get-ChildItem -Path D:\ -Recurse -Depth 100 |Out-GridView
        }
        # Option 8
        if($subsubMenu5 -eq 8){
        ###  8  List empty directory 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      List empty directory        #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder to scan'
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $empty= $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        Get-EmptyDirectory -Path $empty -Recurse |Out-GridView
        }

    }
}
#................................. tools subsubMenu6 ..............................#
function subsubMenu6 {
    $subsubMenu6 = 'X'
    while($subsubMenu6 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    tools subsubmenu 6" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Manage your ISO"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Make random passwords"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Install software"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Execute scripts under the current user while running as SYSTEM using impersonation"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " All color combination for text / background"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " !!!!  be sure what you are doing !!!! secure you Windows 10 /11 Enterprise ,Prof -- automatic - read the information"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " !!!!  be sure what you are doing !!!! another way to secure automated your pc - read the information"

        $subsubMenu6 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu6 -eq 1){
        ###  1 make your ISO  
        cls
         Write-Host "####################################" -ForegroundColor Green 
         Write-Host "#                                  #" -ForegroundColor Green 
         Write-Host "#       make your ISO              #"  -ForegroundColor Green
         Write-Host "#                                  #"  -ForegroundColor Green
         Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green
         Write-Host "#      design : dieter muth        #" -ForegroundColor Green
         Write-Host "#    version : V2.0  / 3-2023      #" -ForegroundColor Green 
         Write-Host "#                                  #"  -ForegroundColor Green
         Write-Host "#                                  #" -ForegroundColor Green 
         Write-Host "#    YOU NEED TO INSTALL ADK       #" -ForegroundColor Green 
         Write-Host "#  and the download  your updates  #"  -ForegroundColor Green
         Write-Host "#      with ex: wsusoffline        #" -ForegroundColor Green 
         Write-Host "####################################" -ForegroundColor Green
          pause
          cls
       $DISMFile = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe'
      If (!(Test-Path $DISMFile)){ Write-Warning "DISM in Windows ADK not found, aborting..."; exit }

        #........................INFO for working path......................................

        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#      select your working path       #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green

        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $work = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        if (!(Test-Path -path $work)) {New-Item -path $work -ItemType Directory}
        if (!(Test-Path -path $work\iso)) {New-Item -path $work\iso -ItemType Directory}
        if (!(Test-Path -path $work\mount)) {New-Item -path $work\mount -ItemType Directory}
        if (!(Test-Path -path $work\setup)) {New-Item -path $work\setup -ItemType Directory}
        if (!(Test-Path -path $work\upd)) {New-Item -path $work\upd -ItemType Directory}

        cls

        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "# copy your ISO to working path \iso  #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        pause
        cls
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#           put in ISO name           #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        $ISOname = Read-Host -Prompt 'put in ISO Name'
        cls
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "# copy your updates to workpath \upd  #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        pause
        cls
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#           put in NEW ISO name       #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        $NewISOname = Read-Host -Prompt 'put in NEW ISO Name'
        cls

        $ISO = "$work\iso\$ISOname.iso"
    
        $MountFolder = "$work\mount"
        $RefImageFolder = "$work\setup"
        $TmpImage = "$RefImageFolder\tmp_install.wim"
        $RefImage = "$RefImageFolder\new.wim"


        # Mount the ISO
        Mount-DiskImage -ImagePath $ISO
        $ISOImage = Get-DiskImage -ImagePath $ISO | Get-Volume
        $ISODrive = [string]$ISOImage.DriveLetter+":"

        $Mount = "$work\mount"
        if (!(Test-Path -path $Mount)) {New-Item -path $Mount -ItemType Directory}
        $RefImageFolder = "$work\RefImageFolder"
        if (!(Test-Path -path $RefImageFolder)) {New-Item -path $RefImageFolder -ItemType Directory}
        XCopy "$ISODrive\Sources\install.wim" $Mount /Y

        do {
        dism /get-imageinfo /imagefile:"$Mount\install.wim"
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#         delete index ?        y/n   #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        $delindex = Read-Host -Prompt 'y / n'
        If($delindex -eq "n"){Break}
        Write-Output "index number ?"
        $index = Read-Host -Prompt 'index'
        Dism /Delete-Image /ImageFile:"$Mount\install.wim" /Index:$index
        dism /get-imageinfo /imagefile:"$Mount\install.wim"
        }
        until ($delindex-eq "n")
        cls

        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#        let´s go one                 #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        pause
        cls

        #.......................select index ......................................
        dism /get-imageinfo /imagefile:"$Mount\install.wim"
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#            mount index              #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        $mountindex = Read-Host -Prompt 'mount index'
        cls
        #........................ coffee ......................................

        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#      next steps will take time      #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#        so take a coffee             #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#          and let me work            #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        pause
        cls
        #........................ working ......................................

        DISM /Mount-Wim /WimFile:"$Mount\install.wim" /Index:$mountindex /MountDir:$RefImageFolder
        #........................ update ......................................
        Dism /Image:"$RefImageFolder" /Add-Package /PackagePath:"$work\upd"

        DISM /unmount-Wim /MountDir:$RefImageFolder /commit
        DISM /Cleanup-Wim 
        
        #........................ create ISO ......................................
        
        if (!(Test-Path -path c:\temp\genISO )) {New-Item -path c:\temp\genISO -ItemType Directory}
        if (!(Test-Path -path c:\temp\NEWISO )) {New-Item -path c:\temp\NEWISO -ItemType Directory}
        $OSCD="c:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\"

        XCopy "$ISODrive" c:\temp\genISO /E /C /Q /I /Y
        XCopy $work\mount\*.wim c:\temp\genISO\sources\install.wim /Y
        cd \

        & "c:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\\Oscdimg.exe" -m -u2 -pEF -u1 -udfver102 -bc:\temp\genISO\efi\microsoft\boot\efisys.bin c:\temp\genISO c:\temp\NEWISO\$NewISOname.iso
        XCopy c:\temp\NEWISO\*.iso $work /E /C /Q /I /Y

        #........................ cleanup ......................................
        
        rd C:\temp\genISO -Recurse
        rd C:\temp\NEWISO -Recurse

        Dismount-DiskImage -DevicePath \\.\$ISODrive
        cls
        #........................ ready ......................................
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#               ready                 #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#            Your ISO is done         #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#    find it in your work folder      #"-ForegroundColor Green
        Write-Host "# find your image in your work folder #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#                                     #"-ForegroundColor Green
        Write-Host "#         thanks for using            #"-ForegroundColor Green
        Write-Host "########   make your ISO   ############"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        pause
        }
        # Option 2
        if($subsubMenu6 -eq 2){
      ###  2  Lists random password  
        Cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        make random password      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Write-Host "#######################################"-ForegroundColor Green 
        Write-Host "# without char :num (0);lower(l)      #"-ForegroundColor Green 
        write-Host "#######################################"-ForegroundColor Green 

        $lengthin = Read-Host "          how long           " 
        $upperin =  Read-Host "    how much upper char      "
        $lowerin =  Read-Host "    how much lower char      "
        $numericin =  Read-Host "    how much numeric char  "
        $specialin =  Read-Host "    how much special char  "

           function Get-RandomPassword {
              param (
        [Parameter(Mandatory)]
        [ValidateRange(4,[int]::MaxValue)]
        [int] $length = $lengthin ,
        [int] $upper = $upperin,
        [int] $lower =  $lowerin,
        [int] $numeric = $numericin,
        [int] $special = $specialin
         )
            if($upper + $lower + $numeric + $special -gt $length) {
                throw "number of upper/lower/numeric/special char must be lower or equal to length"
           }
           $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           $lCharSet = "abcdefghijkmnopqrstuvwxyz"
            $nCharSet = "123456789"
           $sCharSet = "/*-+,!?=()@;:._"
           $charSet = ""
           if($upper -gt 0) { $charSet += $uCharSet }
           if($lower -gt 0) { $charSet += $lCharSet }
           if($numeric -gt 0) { $charSet += $nCharSet }
           if($special -gt 0) { $charSet += $sCharSet }
    
               $charSet = $charSet.ToCharArray()
              $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            $bytes = New-Object byte[]($length)
            $rng.GetBytes($bytes)
 
           $result = New-Object char[]($length)
            for ($i = 0 ; $i -lt $length ; $i++) {
                $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
            }
           $password = (-join $result)
          $valid = $true
          if($upper   -gt ($password.ToCharArray() | Where-Object {$_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
          if($lower   -gt ($password.ToCharArray() | Where-Object {$_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
          if($numeric -gt ($password.ToCharArray() | Where-Object {$_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
          if($special -gt ($password.ToCharArray() | Where-Object {$_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }
 
           if(!$valid) {
         $password = Get-RandomPassword $length $upper $lower $numeric $special
           }
            return $password
            }
           ""
           Get-RandomPassword $lengthin
            ""
            ""
            Write-Host "#     you see       #"-ForegroundColor Green 
           pause
         }       
        # Option 3
        if($subsubMenu6 -eq 3){
        ### 3   install software    
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        install software          #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
                Write-Host "# select your software #"-ForegroundColor Green
                Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $false # Multiple files can be chosen
	    Filter ='' # Specified file types
            }
         [void]$FileBrowser.ShowDialog()
         $software = $FileBrowser.FileName;

        If($FileBrowser.FileNames -like "*\*") {

        # Do something 
	    $FileBrowser.FileName #Lists selected files (optional)
	            }

        else {
         Write-Host "Cancelled by user"
                    }

        Start-Process -Wait -FilePath '$software' -ArgumentList '/s' -PassThru
        }
        # Option 4
        if($subsubMenu6 -eq 4){
        ### 4   install software    
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        execute script            #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        }
        # Option 5
        if($subsubMenu6 -eq 5){
        ### 5 output all the colour combinations for text/background 
        cls 
        Write-Host "##################################################################" -ForegroundColor Green 
        Write-Host "# output all the colour combinations for -forground -background  #"  -ForegroundColor Green
        Write-Host "#                                                                #"  -ForegroundColor Green
        Write-Host "#                      works as designed - no warranty           #"  -ForegroundColor Green 
        Write-Host "#                          design : dieter muth                  #" -ForegroundColor Green 
        Write-Host "#                    version : V 1.0  /2007 - 2023               #" -ForegroundColor Green  
        Write-Host "##################################################################" -ForegroundColor Green
			pause
			cls
        # https://stackoverflow.com/questions/20541456/list-of-all-colors-available-for-powershell/41954792#41954792
        $colors = [enum]::GetValues([System.ConsoleColor])
        Foreach ($bgcolor in $colors){
	    Foreach ($fgcolor in $colors) { Write-Host "$fgcolor|"  -ForegroundColor $fgcolor -BackgroundColor $bgcolor -NoNewLine }
	    Write-Host " on $bgcolor"
        }
        pause
        }
        # Option 6
        if($subsubMenu6 -eq 6){
        ### 6 secure automated your Windows 10 /11 Enterprise ,Prof "  
               cls 
        Write-Host "###################################################################"-ForegroundColor Green 
        Write-Host "#   will automate secure your PC need internet connection         #"-ForegroundColor Green
        Write-Host "#                                                                 #"-ForegroundColor Green 
        Write-Host "#  information you can get at https://simeononsecurity.ch/scripts #"-ForegroundColor Green 
        Write-Host "#  create restore point for you before run the command  !!!       #"-ForegroundColor Green 
        Write-Host "###################################################################"-ForegroundColor Green
        pause
        cls
        enable-computerrestore -drive c:\
        vssadmin resize shadowstorage /on=c: /for=c: /maxsize=5000MB
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 20 /f
        Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'
        iwr -useb 'https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'|iex
        }
        # Option 7
        if($subsubMenu6 -eq 7){
        ###  7   another way to secure automated your pc   
        Write-Host "###################################################################"-ForegroundColor Green 
        Write-Host "#                  will secure your PC                            #"-ForegroundColor Green
        Write-Host "#                                                                 #"-ForegroundColor Green 
        Write-Host "#  based on   https://gist.github.com/mackwage                    #"-ForegroundColor Green 
        Write-Host "#     create restore point for you before run the command         #"-ForegroundColor Green 
        Write-Host "###################################################################"-ForegroundColor Green 
        enable-computerrestore -drive c:\
        vssadmin resize shadowstorage /on=c: /for=c: /maxsize=5000MB
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 20 /f
        Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'
        # Windows 10 Hardening Script
        # This is based mostly on my own personal research and testing. My objective is to secure/harden Windows 10 as much as possible while not impacting usability at all. (Think being able to run on this computer's of family members so secure them but not increase the chances of them having to call you to troubleshoot something related to it later on). References for virtually all settings can be found at the bottom. Just before the references section, you will always find several security settings commented out as they could lead to compatibility issues in common consumer setups but they're worth considering. 
        # Obligatory 'views are my own'. :) 
        # Thank you @jaredhaight for the Win Firewall config recommendations!
        # Thank you @ricardojba for the DLL Safe Order Search reg key! 
        # Thank you @jessicaknotts for the help on testing Exploit Guard configs and checking privacy settings!
        #:: Best script I've found for Debloating Windows 10: https://github.com/Sycnex/Windows10Debloater
        #::
        #::
        #:: Change file associations to protect against common ransomware attacks
        #:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershel
        #:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
        #:: https://support.microsoft.com/en-us/help/883260/information-about-the-attachment-manager-in-microsoft-windows
        #:: ---------------------
        ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
        #::
        #::
        #:: Enable and configure Windows Defender and advanced settings
        #::
        #:: Reset Defender to defaults. Commented out but available for reference
        #::"%programfiles%"\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
        #:: https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#defender-submitsamplesconsent
        #:: https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
        #::
        #:: Start Defender Service
        sc start WinDefend
        #::Enable Windows Defender sandboxing
        setx /M MP_FORCE_USE_SANDBOX 1
        #:: Update signatures
        #"%ProgramFiles%\Windows Defender\MpCmdRun.exe"-SignatureUpdate
        Update-MpSignature
        #:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
        powershell.exe Set-MpPreference -PUAProtection enable
        #:: Enable Defender periodic scanning
        reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
        #:: Enable Cloud functionality of Windows Defender
        powershell.exe Set-MpPreference -MAPSReporting Advanced
        powershell.exe Set-MpPreference -SubmitSamplesConsent 0
        #::
        #:: Enable early launch antimalware driver for scan of boot-start drivers
        #:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
        reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
        #::
        #:: Enable ASR rules in Win10 1903 ExploitGuard to mitigate Office malspam
        #:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
        #:: Note these only work when Defender is your primary AV
        #::
        #:: Block Office Child Process Creation 
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
        #:: Block Process Injection
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
        #:: Block Win32 API calls in macros
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
        #:: Block Office from creating executables
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
        #:: Block execution of potentially obfuscated scripts
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
        #:: Block executable content from email client and webmail
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
        #:: Block JavaScript or VBScript from launching downloaded executable content
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
        #:: Block lsass cred theft
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
        #:: Block untrusted and unsigned processes that run from USB
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
        #:: Block Adobe Reader from creating child processes
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
        #:: Block persistence through WMI event subscription
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
        #:: Block process creations originating from PSExec and WMI commands
        powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
        #::
        #:: Enable Defender exploit system-wide protection
        #:: The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
        #:: powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
        powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError
        #::
        #::
        #:: Enable and Configure Internet Browser Settings
        #::
        #:: Enable SmartScreen for Edge
        reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
        #:: Enable Notifications in IE when a site attempts to install software
        reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
        #:: Disable Edge password manager to encourage use of proper password manager
        reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
        #::
        #::
        #:: Enable and Configure Google Chrome Internet Browser Settings
        #::
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f
        #::
        #::
        #:: Enable and Configure Microsoft Office Security Settings
        #::
        #:: Harden all version of MS Office itself against common malspam attacks
        #:: Disables Macros, enables ProtectedView
        #:: ---------------------
        reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
        #::
        #:: Harden all version of MS Office itself against DDE malspam attacks
        #:: Disables Macros, enables ProtectedView
        #:: ---------------------
        #::
        reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
        reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
        reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
        reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
        reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
        reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
        #::
        #::
        #:: Enable and Configure General Windows Security Settings
        #:: Disables DNS multicast, smart mutli-homed resolution, netbios, powershellv2, printer driver download and printing over http, icmp redirect
        #:: Enables UAC and sets to always notify, Safe DLL loading (DLL Hijacking prevention), saving zone information, explorer DEP, explorer shell protocol protected mode
        #:: ---------------------
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
        wmic /interactive:off nicconfig where (TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1) call SetTcpipNetbios 2
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
        #::
        #:: Prioritize ECC Curves with longer keys
        #::reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f
        #:: Prevent Kerberos from using DES or RC4
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
        #:: Encrypt and sign outgoing secure channel traffic when possible
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
        #::
        #:: Enable SmartScreen
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
        #::
        #:: Enforce device driver signing
        BCDEDIT /set nointegritychecks OFF
        #::
        #:: Windows Update Settings
        #:: Prevent Delivery Optimization from downloading Updates from other computers across the internet
        #:: 1 will restrict to LAN only. 0 will disable the feature entirely
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 1 /f
        #::
        #:: Set screen saver inactivity timeout to 15 minutes
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
        #:: Enable password prompt on sleep resume while plugged in and on battery
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
        #::
        #:: Windows Remote Access Settings
        #:: Disable solicited remote assistance
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
        #:: Require encrypted RPC connections to Remote Desktop
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
        #:: Prevent sharing of local drives via Remote Desktop Session Hosts
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
        #:: 
        #:: Removal Media Settings
        #:: Disable autorun/autoplay on all drives
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
        #::
        #:: Windows Sharing/SMB Settings
        #:: Disable smb1, anonymous access to named pipes/shared, anonymous enumeration of SAM accounts, non-admin remote access to SAM
        #:: Enable optional SMB client signing
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
        #:: Force SMB server signing
        #:: This could cause impact if the Windows computer this is run on is hosting a file share and the other computers connecting to it do not have SMB client signing enabled.
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
        #::
        #:: Harden lsass to help protect against credential dumping (mimikatz) and audit lsass access requests
        #:: Configures lsass.exe as a protected process and disables wdigest
        #:: Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
        #:: ---------------------
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
        #::
        #:: Windows RPC and WinRM settings
        #:: Stop WinRM
        net stop WinRM
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
        #:: Disable WinRM Client Digiest authentication
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
        #:: Disabling RPC usage from a remote asset interacting with scheduled tasks
        reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
        #:: Disabling RPC usage from a remote asset interacting with services
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
        #::
        #:: Biometrics
        #:: Enable anti-spoofing for facial recognition
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
        #:: Disable other camera use while screen is locked
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
        #:: Prevent Windows app voice activation while locked
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
        #:: Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
        #::
        #::
        #:: Enable and configure Windows Firewall
        #::
        NetSh Advfirewall set allprofiles state on
        #::
        #:: Enable Firewall Logging
        netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
        netsh advfirewall set currentprofile logging maxfilesize 4096
        netsh advfirewall set currentprofile logging droppedconnections enable
        #::
        #:: Block all inbound connections on Public profile
        netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
        #:: Enable Windows Defender Network Protection
        powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
        #::
        #:: Block Win32 binaries from making netconns when they shouldn't - specifically targeting native processes known to be abused by bad actors
        #:: ---------------------
        Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        #::
        #::Netsh.exe int ipv6 set int *INTERFACENUMBER* rabaseddnsconfig=disable
        #::https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16898
        #::
        #:: Windows 10 Privacy Settings
        #::
        #:: Set Windows Analytics to limited enhanced if enhanced is enabled
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
        #:: Set Windows Telemetry to security only
        #:: If you intend to use Enhanced for Windows Analytics then set this to "2" instead
        #:: Note my understanding is W10 Home edition will do a minimum of "Basic"
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
        #:: Disable location data
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
        #:: Prevent the Start Menu Search from providing internet results and using your location
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
        #:: Disable publishing of Win10 user activity 
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
        #:: Disable Win10 settings sync to cloud
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
        #:: Disable the advertising ID
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
        #::
        #:: Disable Windows GameDVR (Broadcasting and Recording)
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
        #:: Disable Microsoft consumer experience which prevent notifications of suggested applications to install
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
        #:: Disable websites accessing local language list
        reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
        #:: Prevent toast notifications from appearing on lock screen
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
        #::
        #::
        #:: Enable Advanced Windows Logging
        #::
        #:: Enlarge Windows Event Security Log Size
        wevtutil sl Security /ms:1024000
        wevtutil sl Application /ms:1024000
        wevtutil.exe sl System /ms:1024000
        wevtutil sl "Windows Powershell" /ms:1024000
        wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
        #:: Record command line data in process creation events eventid 4688
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
        #::
        #:: Enabled Advanced Settings
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
        #:: Enable PowerShell Logging
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
        #::
        #:: Enable Windows Event Detailed Logging
        #:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
        #:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
        Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
        Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
        Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
        Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
        Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
        Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
        Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
        Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
        Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
        Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
        Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
        Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
        #::
        #::
        #:: Extra settings commented out but worth considering
        #::
        #:: Uninstall common extra apps found on a lot of Win10 installs
        #:: Obviously do a quick review to ensure it isn't removing any apps you or your user need to use.
        #:: https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
        #:: PowerShell command to reinstall all pre-installed apps below
        #:: Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage"
        powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
        #:: Removed Provisioned Apps
        #:: This will prevent these apps from being reinstalled on new user first logon
        #:: Obviously I manually chose this list. If you truly want to nuke all the provisioned apps, you can use the below commented command in PowerShell
        #:: Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"
        powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"
        #::
        #::
                #:: Extra settings commented out but worth considering
        #::
        #:: Enforce NTLMv2 and LM authentication
        #:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
        #::
        #:: Prevent unencrypted passwords being sent to third-party SMB servers
        #:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
        #::
        #:: Prevent guest logons to SMB servers
        #:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
        #::
        #:: Force SMB server signing
        #:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
        #::
        #:: Enable Windows Defender Application Guard
        #:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
        powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
        #::
        #:: Enable Windows Defender Credential Guard
        #:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
        #::
        #:: The following variant also enables forced ASLR and CFG but causes issues with several third party apps
        #:: powershell.exe Set-Processmitigation -System -Enable DEP,CFG,ForceRelocateImages,BottomUp,SEHOP
        #::
        #:: Block executable files from running unless they meet a prevalence, age, or trusted list criterion
        #:: This one is commented out for now as I need to research and test more to determine potential impact
        #:: powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
        #::
        #:: Enable Windows Defender real time monitoring
        #:: Commented out given consumers often run third party anti-virus. You can run either. 
        powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
        #::
        #:: Disable internet connection sharing
        #:: Commented out as it's not enabled by default and if it is enabled, may be for a reason
        #:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
        #::
        #:: Always re-process Group Policy even if no changes
        #:: Commented out as consumers don't typically use GPO
        #:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f
        #::
        #:: Force logoff if smart card removed
        #:: Set to "2" for logoff, set to "1" for lock
        #:: Commented out as consumers don't typically use smart cards
        #:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f
        #::
        #:: Restrict privileged local admin tokens being used from network 
        #:: Commented out as it only works on domain-joined assets
        #:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
        #::
        #:: Ensure outgoing secure channel traffic is encrytped
        #:: Commented out as it only works on domain-joined assets
        #:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
        #::
        #:: Enforce LDAP client signing
        #:: Commented out as most consumers don't use LDAP auth
        #:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
        #::
        #:: Prevent unauthenticated RPC connections
        #:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
        #::
        #::
        #:: References
        #::
        #:: LLMNR
        #:: https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
        #:: 
        #:: Windows Defender References
        #:: ASR Rules https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
        #:: ASR and Exploit Guard https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard
        #:: ASR Rules https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
        #:: Easy methods to test rules https://demo.wd.microsoft.com/?ocid=cx-wddocs-testground
        #:: Resource on the rules and associated event IDs https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/event-views
        #:: Defender sandboxing https://cloudblogs.microsoft.com/microsoftsecure/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/
        #:: Defender exploit protection https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/customize-exploit-protection
        #:: Application Guard https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/install-wd-app-guard 
        #:: Defender cmdline https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/command-line-arguments-windows-defender-antivirus
        #::
        #:: General hardening references
        #:: LSA Protection https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn408187(v=ws.11)?redirectedfrom=MSDN
        #::
        #:: Microsoft Office References: 
        #:: Disable DDE https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
        #:: Disable macros https://decentsecurity.com/block-office-macros/
        #::
        #:: Debloating
        #:: https://blog.danic.net/how-windows-10-pro-installs-unwanted-apps-candy-crush-and-how-you-stop-it/
        #
        #:: Frameworks and benchmarks
        #:: STIG https://www.stigviewer.com/stig/windows_10/
        pause
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 8
        if($subsubMenu6 -eq 8){
        ##  put your code here
        Write-Host 'Option 1 subsub 6'
            pause

        }

    }
}
###...........................  Network subMenu 4...............................#
function subMenu4 {
    $subMenu4 = 'X'
    while($subMenu4 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Network " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended"
        $subMenu4 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu7
        if($submenu4 -eq 1){
            subsubMenu7
        }
        # Launch subsubmenu8
        if($submenu4 -eq 2){
            subsubMenu8
        }
    }
}
#............................Network subsubMenu7 .......................#
function subsubMenu7 {
    $subsubMenu7 = 'X'
    while($subsubMenu7 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`   Network " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Network card rename"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Network card  set IP"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Network card Information"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Perform DNS lookups"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Check connectivity"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Trace route communications"
        $subsubMenu7 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu7 -eq 1){
        ###  1 Network card rename 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#  will rename your networkcard    #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green 
        pause
        cls
        Write-Host "                      see your network card s                  "  -foregroundcolor green
        netsh interface ipv4 show interfaces
        pause
        $Card = read-host " give me the name of your network card to rename " 
        $newName = read-host " give me the NEW name of your network card " 
        Get-NetAdapter -Name "$Card" | Rename-NetAdapter -NewName $newName
        netsh interface ipv4 show interfaces
        pause
        Write-Host "                      done                   "  -foregroundcolor green
        pause
        }
        # Option 2
        if($subsubMenu7 -eq 2){
        ###  2  set static IP  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#         set static IP            #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green 
        pause
        cls
        #set static IP address
        Write-Host "                      you want to set a fixed IP ?                    "  -foregroundcolor green
        pause
        netsh interface ipv4 show interfaces
        pause

        $Card = read-host " give me the name of your network we need too modify to static "
        $ipaddress =  read-host " give me the IP  ex: 192.168.0.1 "
        $ipprefix =  read-host " give me the prefix ex: :255.255.255.0 "
        $ipgw =  read-host " give me the IP of your gateway  ex:192.168.0.254"
        $ipdns =  read-host " give me the IP of your DNS Server"
        $ipif

        #set static IP address

        netsh int ip set address "$Card" static "$ipaddress" "$ipprefix" "$ipgw"  1

        $ipif = (Get-NetAdapter).ifIndex
        New-NetIPAddress -IPAddress $ipaddress -PrefixLength $ipprefix `
        -InterfaceIndex $ipif -DefaultGateway $ipgw

        Get-NetAdapter -Name "$Card" | Get-NetIPConfiguration

        Write-Host "                      done                   "  -foregroundcolor green

        pause
        }
        # Option 3
        if($subsubMenu7 -eq 3){
        ###  3  Network card Information
         cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#    Network card Information      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        $Data = @()
        $NetInfo = Get-NetIPConfiguration -Detailed 
        foreach ( $nic in $Netinfo) { 
         foreach ($ip in $nic.IPv4Address) { 
        $Data += [pscustomobject] @{ Ordinateur=$nic.ComputerName; AliasNIC=$nic.InterfaceAlias; 
                                    NetworkcardName=$nic.InterfaceDescription; IP=$ip; MAC=$nic.NetAdapter.MACAddress;
                                    Status=$nic.NetAdapter.Status
                                    }
        }
        } 
        $Data | Format-Table #-HideTableHeader
        pause
        }
        # Option 4
        if($subsubMenu7 -eq 4){
        ###  4  Perform DNS lookups 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        Perform DNS lookups       #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        $DNS = Read-Host -Prompt 'put in the web/ip/hostname '
        Resolve-DnsName "$DNS" 
        pause
        }
        # Option 5
        if($subsubMenu7 -eq 5){
        ###  5  Check connectivity   
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       Check connectivity         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        $Trace = Read-Host -Prompt 'put in the web/ip/hostname '
        test-netconnection "$Trace" -InformationLevel "Detailed" 
        pause
        }
        # Option 6
        if($subsubMenu7 -eq 6){
        ###  6  Trace route communications  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#    Trace route communications    #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        $Trace = Read-Host -Prompt 'put in the web/ip/hostname '
        Test-NetConnection "$Trace" -traceroute
        pause
        }

    }
}
#.................................Network subsubMenu8 ..............................#
function subsubMenu8 {
    $subsubMenu8 = 'X'
    while($subsubMenu8 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`   Network " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Get information about your Network - Name,IP,Mac,Vendor,ports..."
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Check connectivity based on list"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Check connectivity based on port or service"

        $subsubMenu8 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu8 -eq 1){
        ### 1   get information about your Network
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#get information about your Network#"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
        Write-Host ""
        Write-Host "##    Flush the local arp cache for most accurate results   ##" -ForegroundColor Green
        	pause
			cls
        
        If (-not(Get-InstalledModule AdminToolbox -ErrorAction SilentlyContinue)) {
        Write-Host "Module AdminToolbox does not exist  ---  go and install / download  "  -ForegroundColor red -BackgroundColor Gray
        pause
        break
        }
        Else {
         Write-Host "Module exists"
        }
        netsh interface IP delete arpcache
        $CIDR = Read-Host -Prompt 'put IP or IP Range (ex: 10.0.0.0/24)'
        cls
        Invoke-NetworkScan -CIDR $CIDR -DeepScan | Out-GridView
        }
        # Option 2
        if($subsubMenu8 -eq 2){
        ###  2   Check connectivity based on list  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "# Check connectivity based on list #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Write-Host "# select your List #"-ForegroundColor Green
                Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $false # Multiple files can be chosen
	    Filter ='files (*.csv, *.txt)|*.csv;*.txt' # Specified file types
            }
         [void]$FileBrowser.ShowDialog()
         $complist = $FileBrowser.FileName;

        If($FileBrowser.FileNames -like "*\*") {

        # Do something 
	    $FileBrowser.FileName #Lists selected files (optional)
	            }
        else {
         Write-Host "Cancelled by user"
                    }
              
        $complist = Get-Content "$complist"
        foreach($comp in $complist){
        $pingtest = Test-Connection -ComputerName $comp -Quiet -Count 1 -ErrorAction SilentlyContinue
        if($pingtest){
        Write-Host($comp + " is online")
          }
          else{
        Write-Host($comp + " is not reachable")
             }
             }
                pause
        }
        # Option 3
        if($subsubMenu8 -eq 3){
        ###  3  Check connectivity based on port or service 
         cls       
        Write-Host "#################################################" -ForegroundColor Green  
        Write-Host "#  Check connectivity based on port or service  #"  -ForegroundColor Green 
        Write-Host "#                                               #"  -ForegroundColor Green 
        Write-Host "#          works as designed - no warranty      #"  -ForegroundColor Green 
        Write-Host "#              design : dieter muth             #" -ForegroundColor Green 
        Write-Host "#          version : V 1.0  /2007 - 2023        #" -ForegroundColor Green  
        Write-Host "#################################################" -ForegroundColor Green
			pause
			cls
        $Trace = Read-Host -Prompt 'put in the web/ip/hostname '
        $port = Read-Host -Prompt 'put in port '
        Test-NetConnection "$Trace" -port "$port"
        pause

        }

    }
}
###..........................Active Directory subMenu5...............................#
function subMenu5 {
    $subMenu5 = 'X'
    while($subMenu5 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Active Directory " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu5 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu9
        if($submenu5 -eq 1){
            subsubMenu9
        }
        # Launch subsubmenu10
        if($submenu5 -eq 2){
            subsubMenu10
        }
    }
}
#............................Active Directory subsubMenu9 .......................#
function subsubMenu9 {
    $subsubMenu9 = 'X'
    while($subsubMenu9 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Active Directory " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Gets info on local domain"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subsubMenu9 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu9 -eq 1){
        ### 1   Gets info on local domain  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#    Gets info on local domain     #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        get-adinfo
        pause
        }
        # Option 2
        if($subsubMenu9 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 9'
            pause
        }

    }
}
#.................................Active Directory subsubMenu10 ..............................#
function subsubMenu10 {
    $subsubMenu10 = 'X'
    while($subsubMenu10 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Active Directory " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subsubMenu10 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu10 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 10'
            pause
        }
        # Option 2
        if($subsubMenu10 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 10'
            pause
        }

    }
}
###...........................Endpoint Management subMenu6...............................#
function subMenu6 {
    $subMenu6 = 'X'
    while($subMenu6 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Endpoint Management" -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu6 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu11
        if($submenu6 -eq 1){
            subsubMenu11
        }
        # Launch subsubmenu12
        if($submenu6 -eq 2){
            subsubMenu12
        }
    }
}
#............................Endpoint Management subsubMenu11 .......................#
function subsubMenu11 {
    $subsubMenu11 = 'X'
    while($subsubMenu11 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Endpoint Management subsubmenu 11" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Endpoint Management main part sub  sub 11"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Endpoint Management main part sub  sub 11"
        $subsubMenu11 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu11 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 11'
            pause
        }
        # Option 2
        if($subsubMenu11 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 11'
            pause
        }

    }
}
#................................. Endpoint Management subsubMenu 12 ..............................#
function subsubMenu12 {
    $subsubMenu12 = 'X'
    while($subsubMenu12 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Endpoint Management subsubmenu 12" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white "Endpoint Management  main part sub  sub 12"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow "Endpoint Management  main part sub  sub 12"
        $subsubMenu12 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu12 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 12'
            pause
        }
        # Option 2
        if($subsubMenu12 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 12'
            pause
        }

    }
}
###...........................Exchange subMenu7...............................#
function subMenu7 {
    $subMenu7 = 'X'
    while($subMenu7 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Exchange " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu7 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu13
        if($submenu7 -eq 1){
            subsubMenu13
        }
        # Launch subsubmenu14
        if($submenu7 -eq 2){
            subsubMenu14
        }
    }
}
#............................Exchange subsubMenu13 .......................#
function subsubMenu13 {
    $subsubMenu13 = 'X'
    while($subsubMenu13 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Exchange subsubmenu 13" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Exchange main part sub  sub 13"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Exchange main part sub  sub 13"
        $subsubMenu13 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu13 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 13'
            pause
        }
        # Option 2
        if($subsubMenu13 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 13'
            pause
        }

    }
}
#................................. Exchange subsubMenu 14 ..............................#
function subsubMenu14 {
    $subsubMenu14 = 'X'
    while($subsubMenu14 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Exchange subsubmenu 14" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Exchange main part sub  sub 14"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Exchange main part sub  sub 14"
        $subsubMenu14 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu14 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 14'
            pause
        }
        # Option 2
        if($subsubMenu14 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 14'
            pause
        }

    }
}
###...........................Office 365 subMenu 8...............................#
function subMenu8 {
    $subMenu8 = 'X'
    while($subMenu8 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Office 365" -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu8 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu15
        if($submenu8 -eq 1){
            subsubMenu15
        }
        # Launch subsubmenu16
        if($submenu8 -eq 2){
            subsubMenu16
        }
    }
}
#............................Office 365 subsubMenu15 .......................#
function subsubMenu15 {
    $subsubMenu15 = 'X'
    while($subsubMenu15 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Office 365 subsubmenu 15" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Office 365 main part sub  sub 15"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Office 365 main part sub  sub 15"
        $subsubMenu15 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu15 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 15'
            pause
        }
        # Option 2
        if($subsubMenu15 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 15'
            pause
        }

    }
}
#.................................Office 365 subsubMenu 16 ..............................#
function subsubMenu16 {
    $subsubMenu16 = 'X'
    while($subsubMenu16 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Office 365 subsubmenu 16" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Office 365 main part sub  sub 16"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Office 365 main part sub  sub 16"
        $subsubMenu16 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu16 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 16'
            pause
        }
        # Option 2
        if($subsubMenu16 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 16'
            pause
        }

    }
}
###...........................Remoting subMenu 9...............................#
function subMenu9 {
    $subMenu9 = 'X'
    while($subMenu9 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`   home of Remoting" -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended"
        $subMenu9 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu17
        if($submenu9 -eq 1){
            subsubMenu17
        }
        # Launch subsubmenu18
        if($submenu9 -eq 2){
            subsubMenu18
        }
    }
}
#............................Remoting subsubMenu17 .......................#
function subsubMenu17 {
    $subsubMenu17 = 'X'
    while($subsubMenu17 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Remoting " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Connect-SSH"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Enable-Remoting remote"
        $subsubMenu17 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu17 -eq 1){
        ###  1   Connect-SSH 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#                                  #" -ForegroundColor Green  
        Write-Host "#          Connect-SSH             #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
 
        $account = Read-Host - " provide account "
        $host = Read-Host - " provide hostname "
        Connect-SSH -User "$account" -Server "$host"

        }
        # Option 2
        if($subsubMenu17 -eq 2){
        ### 2  Enable-Remoting 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#        Enable-Remoting           #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Enable-Remoting
        }

    }
}
#................................. Remoting subsubMenu 18 ..............................#
function subsubMenu18 {
    $subsubMenu18 = 'X'
    while($subsubMenu18 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Remoting subsubmenu 18" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Get-TerminalSessions"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Install-SSH"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Runas agains any program with provided network credentials"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Invokes a Service restart on all endpoints"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Removes Terminal Server User Sessions"

                $subsubMenu18 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu18 -eq 1){
        ###  1  Get-TerminalSessions 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#     Get-TerminalSessions         #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Get-TerminalSessions
        }
        # Option 2
        if($subsubMenu18 -eq 2){
        ###  2   Install-SSH  
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#      Install-SSH as feature      #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Install-SSH -InstallAsFeature
        }
        # Option 3
        if($subsubMenu18 -eq 3){
        ### 3 invoke-RunAsNetwork
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       invoke-RunAsNetwork        #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        invoke-RunAsNetwork
        }
        # Option 4
        if($subsubMenu18 -eq 4){
        ### 4  Invoke-ServiceRecovery 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       Invoke-ServiceRecovery     #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Invoke-ServiceRecovery
        }
        # Option 5
        if($subsubMenu18 -eq 5){
        ### 5 Remove-TerminalSessions 
        cls 
        Write-Host "####################################" -ForegroundColor Green  
        Write-Host "#       Remove-TerminalSessions    #"  -ForegroundColor Green 
        Write-Host "#                                  #"  -ForegroundColor Green 
        Write-Host "# works as designed - no warranty  #"  -ForegroundColor Green 
        Write-Host "#      design : dieter muth        #" -ForegroundColor Green 
        Write-Host "#  version : V 1.0  /2007 - 2023   #" -ForegroundColor Green  
        Write-Host "####################################" -ForegroundColor Green
			pause
			cls
        Remove-TerminalSessions
        }

    }
}
###...........................VMWARE subMenu10...............................#
function subMenu10 {
    $subMenu10 = 'X'
    while($subMenu10 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of VMWARE " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu10 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu19
        if($submenu10 -eq 1){
            subsubMenu19
        }
        # Launch subsubmenu20
        if($submenu10 -eq 2){
            subsubMenu20
        }
    }
}
#............................VMWARE subsubMenu19 .......................#
function subsubMenu19 {
    $subsubMenu19 = 'X'
    while($subsubMenu19 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    VMWARE subsubmenu 19" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " VMWARE main part sub  sub 19"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " VMWARE main part sub  sub 19"
        $subsubMenu19 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu19 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 1'
            pause
        }
        # Option 2
        if($subsubMenu19 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 1'
            pause
        }

    }
}
#................................. VMWARE subsubMenu20 ..............................#
function subsubMenu20 {
    $subsubMenu20 = 'X'
    while($subsubMenu20 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    VMWARE subsubmenu 20" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " VMWARE main part sub  sub 20"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " VMWARE main part sub  sub 20"
        $subsubMenu20 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu20 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 20'
            pause
        }
        # Option 2
        if($subsubMenu20 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 20'
            pause
        }

    }
}
###...........................Lab subMenu11...............................#
function subMenu11 {
    $subMenu11 = 'X'
    while($subMenu11 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Lab submenu11" -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basics"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n "
        $subMenu11 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu 21
        if($submenu11 -eq 1){
            subsubMenu21
        }
        # Launch subsubmenu22
        if($submenu11 -eq 2){
            subsubMenu22
        }
    }
}
#............................Lab subsubMenu 21 .......................#
function subsubMenu21 {
    $subsubMenu21 = 'X'
    while($subsubMenu21 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Lab" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " READ this Link "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subsubMenu21 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu21 -eq 1){
        ### 1 read this link
        Start-Process https://automatedlab.org/en/latest/Wiki/Basic/gettingstarted/
        }
        # Option 2
        if($subsubMenu21 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 21'
            pause
        }
        # Option 3
        if($subsubMenu21 -eq 3){
        ##  put your code here
            Write-Host 'Option 1 subsub 21'
            pause
        }
        # Option 4
        if($subsubMenu21 -eq 4){
        ##  put your code here
            Write-Host 'Option 2 subsub 21'
            pause
        }
        # Option 5
        if($subsubMenu21 -eq 5){
        ##  put your code here
            Write-Host 'Option 1 subsub 21'
            pause
        }
        # Option 6
        if($subsubMenu21 -eq 6){
        ##  put your code here
            Write-Host 'Option 2 subsub 21'
            pause
        }

    }
}
#................................. Lab subsubMenu22 ..............................#
function subsubMenu22 {
    $subsubMenu22 = 'X'
    while($subsubMenu22 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Lab " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Lab main part sub  sub 22"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Lab main part sub  sub 22"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Lab main part sub  sub 22"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Lab main part sub  sub 22"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Lab main part sub  sub 22"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Lab main part sub  sub 22"
        $subsubMenu22 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu22 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 22'
            pause
        }
        # Option 2
        if($subsubMenu22 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 22'
            pause
        }
        # Option 3
        if($subsubMenu22 -eq 3){
        ##  put your code here
            Write-Host 'Option 1 subsub 22'
            pause
        }
        # Option 4
        if($subsubMenu22 -eq 4){
        ##  put your code here
            Write-Host ' Option 2 subsub 22'
            pause
        }
        # Option 5
        if($subsubMenu22 -eq 5){
        ##  put your code here
            Write-Host 'Option 1 subsub 22'
            pause
        }
        # Option 6
        if($subsubMenu22 -eq 6){
        ##  put your code here
            Write-Host ' Option 2 subsub 22'
            pause
        }

    }
}
###...........................Everything with MDT subMenu 12...............................#
function subMenu12 {
    $subMenu12 = 'X'
    while($subMenu12 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Everything with MDT " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu12 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu23
        if($submenu12 -eq 1){
            subsubMenu23
        }
        # Launch subsubmenu24
        if($submenu12 -eq 2){
            subsubMenu24
        }
    }
}
#............................Everything with MDT subsubMenu23 .......................#
function subsubMenu23 {
    $subsubMenu23 = 'X'
    while($subsubMenu23 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Everything with MDT subsubmenu 23 " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Everything with MDT main part sub  sub 23"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Everything with MDT main part sub  sub 23"
        $subsubMenu23 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu23 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 23'
            pause
        }
        # Option 2
        if($subsubMenu23 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 23'
            pause
        }

    }
}
#................................. Everything with MDT subsubMenu24 ..............................#
function subsubMenu24 {
    $subsubMenu24 = 'X'
    while($subsubMenu24 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Everything with MDT subsubmenu 24" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Everything with MDT main part sub  sub 24"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Everything with MDT main part sub  sub 24"
        $subsubMenu24 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu24 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 24'
            pause
        }
        # Option 2
        if($subsubMenu24 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 24'
            pause
        }

    }
}
###...........................Windows Client subMenu 13...............................#
function subMenu13 {
    $subMenu13 = 'X'
    while($subMenu13 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Windows Client " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu13 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu25
        if($submenu13 -eq 1){
            subsubMenu25
        }
        # Launch subsubmenu26
        if($submenu13 -eq 2){
            subsubMenu26
        }
    }
}
#............................Windows Client subsubMenu25 .......................#
function subsubMenu25 {
    $subsubMenu25 = 'X'
    while($subsubMenu25 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Windows Client subsubmenu 25" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows Client main part sub  sub 25"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Windows Client main part sub  sub 25"
        $subsubMenu25 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu25 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 25'
            pause
        }
        # Option 2
        if($subsubMenu25 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 25'
            pause
        }

    }
}
#................................. Windows Client subsubMenu26 ..............................#
function subsubMenu26 {
    $subsubMenu26 = 'X'
    while($subsubMenu26 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Windows Client subsubmenu 26" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows Client main part sub  sub 26"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Windows Client main part sub  sub 26"
        $subsubMenu26 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu26 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 26'
            pause
        }
        # Option 2
        if($subsubMenu26 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 26'
            pause
        }

    }
}
###...........................Windows Server subMenu14...............................#
function subMenu14 {
    $subMenu14 = 'X'
    while($subMenu14 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`   home of Windows Server " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu14 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu27
        if($submenu14 -eq 1){
            subsubMenu27
        }
        # Launch subsubmenu28
        if($submenu14 -eq 2){
            subsubMenu28
        }
    }
}
#............................Windows Server subsubMenu27 .......................#
function subsubMenu27 {
    $subsubMenu27 = 'X'
    while($subsubMenu27 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Windows Server subsubmenu 27" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows Server main part sub  sub 27"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Windows Server main part sub  sub 27"
        $subsubMenu27 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu27 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 1'
            pause
        }
        # Option 2
        if($subsubMenu27 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 1'
            pause
        }

    }
}
#.................................Windows Server subsubMenu28 ..............................#
function subsubMenu28 {
    $subsubMenu28 = 'X'
    while($subsubMenu28 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Windows Server subsubmenu 28" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Windows Server main part sub  sub 28"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Windows Server main part sub  sub 28"
        $subsubMenu28 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu28 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 2'
            pause
        }
        # Option 2
        if($subsubMenu28 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 2'
            pause
        }

    }
}
###...........................Linux Client subMenu15...............................#
function subMenu15 {
    $subMenu15 = 'X'
    while($subMenu15 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Linux Client " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu15 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu29
        if($submenu15 -eq 1){
            subsubMenu29
        }
        # Launch subsubmenu30
        if($submenu15 -eq 2){
            subsubMenu30
        }
    }
}
#............................Linux Client subsubMenu29 .......................#
function subsubMenu29 {
    $subsubMenu29 = 'X'
    while($subsubMenu29 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Linux Client subsubmenu 29" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Linux Client main part sub  sub 29"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Linux Client main part sub  sub 29"
        $subsubMenu29 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu29 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 29'
            pause
        }
        # Option 2
        if($subsubMenu29 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 29'
            pause
        }

    }
}
#.................................Linux Client subsubMenu30 ..............................#
function subsubMenu30 {
    $subsubMenu30 = 'X'
    while($subsubMenu30 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Linux Client subsubmenu 30" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Linux Client main part sub  sub 30"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Linux Client main part sub  sub 30"
        $subsubMenu30 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu30 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 30'
            pause
        }
        # Option 2
        if($subsubMenu30 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 30'
            pause
        }

    }
}
###...........................Linux Server subMenu 16...............................#
function subMenu16 {
    $subMenu16 = 'X'
    while($subMenu16 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Linux Server " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu16 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu31
        if($submenu16 -eq 1){
            subsubMenu31
        }
        # Launch subsubmenu32
        if($submenu16 -eq 2){
            subsubMenu32
        }
    }
}
#............................Linux Server subsubMenu31 .......................#
function subsubMenu31 {
    $subsubMenu31 = 'X'
    while($subsubMenu31 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Linux Server subsubmenu 31" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Linux Server main part sub  sub 31"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Linux Server main part sub  sub 31"
        $subsubMenu31 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu31 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 31'
            pause
        }
        # Option 2
        if($subsubMenu31 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 31'
            pause
        }

    }
}
#................................. Linux Server subsubMenu32  ..............................#
function subsubMenu32 {
    $subsubMenu32 = 'X'
    while($subsubMenu32 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Linux Server subsubmenu 22" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Linux Server main part sub  sub 32"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Linux Server main part sub  sub 32"
        $subsubMenu32 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu32 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 32'
            pause
        }
        # Option 2
        if($subsubMenu32 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 32'
            pause
        }

    }
}
###...........................Powershell tools subMenu98...............................#
function subMenu98 {
    $subMenu98 = 'X'
    while($subMenu98 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of Powershell tools " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended"
        $subMenu98 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu33
        if($submenu98 -eq 1){
            subsubMenu33
        }
        # Launch subsubmenu34
        if($submenu98 -eq 2){
            subsubMenu34
        }
    }
}
#............................Powershell tools subsubMenu33 .......................#
function subsubMenu33 {
    $subsubMenu33 = 'X'
    while($subsubMenu33 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Powershell tools subsubmenu 33" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " n.n"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n "
        $subsubMenu33 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu33 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 33'
            pause
        }
        # Option 2
        if($subsubMenu33 -eq 2){
        ##  put your code here
            Write-Host 'Option 2 subsub 33'
            pause
        }

    }
}
#................................. Powershell tools subsubMenu34 ..............................#
function subsubMenu34 {
    $subsubMenu34 = 'X'
    while($subsubMenu34 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Powershell tools " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " list comments with line in powershell script"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " select pattern inside script"
        $subsubMenu34 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu34 -eq 1){
       ###  1  list comments with line in powershell script  
        Function Get-Comment
        {
        Param([Parameter(Position=0)] [String] $FilePath,[Switch] $FromClipBoard)

            If($FilePath)
         {
        $Content = Get-Content $FilePath
         }
          elseif($FromClipBoard)
         {
        $Content = [Windows.clipboard]::GetText()
         }
         else
         {
        Write-Host "Please provide a file/content to look for comments."
          }

         $CommentTokens =  [System.Management.Automation.PSParser]::Tokenize($Content, [ref]$null) | `
        Where-Object{$_.type -like "*comment*"}

         Foreach($obj in $CommentTokens)
            {
        $IndentSpace = ""
        If($obj.StartColumn -gt 1)
        {
            1..($obj.startcolumn - 1)| %{[String]$IndentSpace += " "}
            #$IndentSpace+$obj.content
        }
    
        ''| select @{n='Line';e={$obj.StartLine}}, @{n="Comment";e={$IndentSpace+$obj.Content}}
          }
        }

        write-host ""
        write-host ""
        $PSpath = Read-Host "          put in path to the ps script ex: c:\tmp\ *.ps1     " 
        get-comment -FilePath "$PSpath" | Out-GridView
        }
        # Option 2
        if($subsubMenu34 -eq 2){
        ###  2  find pattern in script 
        Write-Host "#######################################"-ForegroundColor Green
        Write-Host "#        find pattern in script       #"-ForegroundColor Green
        Write-Host "#######################################"-ForegroundColor Green
        pause
        cls
        Write-Host""
        Write-Host""
        Write-Host""
        read-host $pattern = " what are you want to look "
        Write-Host "           Select the source file            "
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $false # Multiple files can be chosen
	    Filter = 'files (*.*)|*.*' # Specified file types
            }
         [void]$FileBrowser.ShowDialog()
         $file = $FileBrowser.FileName;

        If($FileBrowser.FileNames -like "*\*") {

        # Do something 
	    $FileBrowser.FileName #Lists selected files (optional)
	            }

        else {
         Write-Host "Cancelled by user"
                    }
                    
        # Load the script content
        $scriptContent = Get-Content -file "$file"

        # Use regex to find lines with ?? operator
        #$pattern = '(\$*=)'
        $matches = $scriptContent | Select-String -Pattern $pattern

        # Create objects with line number and line content
        $lineData = foreach ($match in $matches) {
            [PSCustomObject]@{
        LineNumber = $match.LineNumber
        Line = $match.Line
             }
        }
        # Display the lines with $= operator
        $lineData | Out-GridView

        }
    }
}
###...........................Fun subMenu 99...............................#
function subMenu99 {
    $subMenu99 = 'X'
    while($subMenu99 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`   home of Fun " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic "
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subMenu99 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu35
        if($submenu99 -eq 1){
            subsubMenu35
        }
        # Launch subsubmenu36
        if($submenu99 -eq 2){
            subsubMenu36
        }
    }
}
#............................Fun subsubMenu35 .......................#
function subsubMenu35 {
    $subsubMenu35 = 'X'
    while($subsubMenu35 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Fun " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Encounters"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " ImperialMarch"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " MissionImpossible"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Mario"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " i speak"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " n.n"
        $subsubMenu35 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu35 -eq 1){
        ###  1  Get-CloseEncounters 
        cls
        Get-CloseEncounters
        }
        # Option 2
        if($subsubMenu35 -eq 2){
        ###  2   Get-ImperialMarch 
		cls
        Get-ImperialMarch
        }
        # Option 3
        if($subsubMenu35 -eq 3){
        ###  3  Get-MissionImpossible 
		cls
        Get-MissionImpossible
        }
        # Option 4
        if($subsubMenu35 -eq 4){
        ### 4  Get-Mario 
        cls 
        Get-Mario 
        }
        # Option 5
        if($subsubMenu35 -eq 5){
        ###  5  i speak  
        Write-Host "#################################################################"-ForegroundColor Green 
        Write-Host "#                           i speak                             #"-ForegroundColor Green
        Write-Host "#################################################################"-ForegroundColor Green 
            Write-Host "" 
            $Expression = read-host "give me what to say :"
            cls
            Write-Host ""
            Write-Host "" 
            Invoke-Speak -Expression "$Expression"
        }
        # Option 6
        if($subsubMenu35 -eq 6){
        ##  put your code here
            Write-Host 'Option 2 subsub 35'
            pause
        }
        
    }
 }

#................................. Fun subsubMenu36 ..............................#
function subsubMenu36 {
    $subsubMenu36 = 'X'
    while($subsubMenu36 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    Fun subsubmenu 36" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Fun main part sub  sub 36"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Fun main part sub  sub 36"
        $subsubMenu36 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu36 -eq 1){
        ##  put your code here
            Write-Host 'Option 1 subsub 36'
            pause
        }
        # Option 2
        if($subsubMenu36 -eq 2){
        ##  put your code here
            Write-Host ' Option 2 subsub 36'
            pause
        }

    }
}
###...........................for this script subMenu100...............................#
function subMenu100 {
    $subMenu100 = 'X'
    while($subMenu100 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    home of for this script " -ForegroundColor Magenta
        Write-Host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " basic"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " extended"
        $subMenu100 = Read-Host "`nSelection (leave blank to quit)"
        
        # Launch subsubmenu37
        if($submenu100 -eq 1){
            subsubMenu37
        }
        # Launch subsubmenu38
        if($submenu100 -eq 2){
            subsubMenu38
        }
    }
}
#............................for this script subsubMenu37 .......................#
function subsubMenu37 {
    $subsubMenu37 = 'X'
    while($subsubMenu37 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    for this script " -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " List installed modules"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Update all installed modules"
        $subsubMenu37 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu37 -eq 1){
        ### 1  List installed modules 
         Write-Host "##############################################################"-ForegroundColor green
         Write-Host "                  List installed modules                      "-ForegroundColor green
         Write-Host "##############################################################"-ForegroundColor green
            cls
            Get-InstalledModule |Out-GridView *
        }
        # Option 2
        if($subsubMenu37 -eq 2){
        ### 2  update all installed modules 
         Write-Host "##############################################################"-ForegroundColor green
         Write-Host " update all installed modules    - you need internet          "-ForegroundColor green
         Write-Host "##############################################################"-ForegroundColor green
            cls
            Update-Module
        }

    }
}
#................................. for this script subsubMenu38 ..............................#
function subsubMenu38 {
    $subsubMenu38 = 'X'
    while($subsubMenu38 -ne ''){
        Clear-Host
        write-host ""
        write-host ""
        Write-Host "`    for this script subsubmenu 38" -ForegroundColor Magenta
        write-host ""
        write-host ""
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Download powershell modules for this script"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Download powershell modules"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor white " Install the modules offline"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
        Write-Host -ForegroundColor yellow " Copy the script and start from the new folder"
        $subsubMenu38 = Read-Host "`nSelection (leave blank to quit)"
                
        # Option 1
        if($subsubMenu38 -eq 1){
        ### 1  download powershell modules for this script 
        Write-Host "####################################################################################################################################"-ForegroundColor Green 
        Write-Host "#                              download  modules for this script to a folder on a pc with internet                                 #"-ForegroundColor Green
        Write-Host "#                                                                                                                                  #"-ForegroundColor Green 
        Write-Host "#  If you get :                                                                                                                    #"-ForegroundColor magenta 
        Write-Host "#  Install-Module: Unable to download from URI.Unable to download the list of available providers. Check your internet connection. #"-ForegroundColor magenta
        Write-Host "#                                                                                                                                  #"-ForegroundColor magenta
        Write-Host "#  you need to :  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 in powershell                    #"-ForegroundColor magenta
        Write-Host "#                                                                                                                                  #"-ForegroundColor magenta
        Write-Host "####################################################################################################################################"-ForegroundColor Green 
        pause
        cls
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Host "select the folder to download the modules"-ForegroundColor Green

                       Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $Modules = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        Save-Module -Name RobocopyPS -Path “$Modules”
        Save-Module -Name PSWindowsUpdate -Path “$Modules”
        Save-Module -Name AdminToolbox -Path “$Modules”
        Save-Module -Name RunAsUser -Path “$Modules”
        save-Module -Name xHyper-V -Path “$Modules”
        Save-Module -Name PSHyperVTools -Path “$Modules”
        Save-Module -Name AutomatedLab -Path “$Modules”
          Write-Host "done"-ForegroundColor Green
        pause
        }
        # Option 2
        if($subsubMenu38 -eq 2){
        ### 2  download powershell modules  
        Write-Host "#############################################################################"-ForegroundColor Green 
        Write-Host "#   download  modules to a folder on a pc with internet                     #"-ForegroundColor Green
        Write-Host "#############################################################################"-ForegroundColor Green 
        pause
        cls
        $moduldown = Read-Host "give me the name of the modul ( ex: robocopyps ) " 
        Write-Host "select the folder to download the module"-ForegroundColor Green

        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $Modul = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        Save-Module -Name "$moduldown" -Path “$Modul”

          Write-Host "done"-ForegroundColor Green
        pause
        }
        # Option 3
        if($subsubMenu38 -eq 3){
        ### 3  install the modules   offline 
        Write-Host "#################################################################"-ForegroundColor Green 
        Write-Host "#           install the modules   offline                       #"-ForegroundColor Green
        Write-Host "#################################################################"-ForegroundColor Green 
               pause
               cls
               Write-Host "select the folder of the modules"-ForegroundColor Green

        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the source folder '
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
        $Modulesoffline = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        }

        #Copy the module to "C:\Program Files\WindowsPowerShell\Modules"
        Copy-Item -Path "$Modulesoffline\*" -Destination "C:\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
        Write-Host "done"-ForegroundColor Green
        pause
        }
        # Option 4
        if($subsubMenu38 -eq 4){
         ### 4  copy the script , exit this and start from the new folder
        Write-Host "##############################################################"-ForegroundColor green
        Write-Host "                 will copy to folder you select          2   "-ForegroundColor green
        Write-Host "          and make a shortcut to the desktop for you       "-ForegroundColor green
        Write-Host "##############################################################"-ForegroundColor green
        Add-Type -AssemblyName System.Windows.Forms
        $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $FolderBrowser.Description = 'Select the folder containing the reports'
        $result = $FolderBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
        if ($result -eq [Windows.Forms.DialogResult]::OK){
            $stuff = $FolderBrowser.SelectedPath
        }
        else {
           Write-Host "Cancel button pushed. Exiting script"
        
        }
       $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')

        $ScriptName = $MyInvocation.MyCommand.Name
        Write-Output "`Name of the script : $scriptname"

        $mypath = $MyInvocation.MyCommand.Path
        Write-Output "Path of the script : $mypath"
        Write-Host "           will copy to folder you select and start       "-ForegroundColor green
        Write-Host "           you need to close the old powershell           "-ForegroundColor green
        pause
        cd $mypath
        Copy "$ScriptName" "$stuff"
        CD $stuff

        $SourceFilePath = "$stuff\$ScriptName"
        $ShortcutPath = "C:\Users\$env:UserName\Desktop\$ScriptName.lnk"
        $WScriptObj = New-Object -ComObject ("WScript.Shell")
        $shortcut = $WscriptObj.CreateShortcut($ShortcutPath)
        $shortcut.TargetPath = $SourceFilePath
        pause
        $shortcut.Save()

        #New-Item -ItemType $SymbolicLink -Path "$stuff" -Name "$ScriptName" -Value "$stuff\$ScriptName"
        Start-Process PowerShell -WindowStyle Maximized -ArgumentList "-noexit -command .\$scriptname" 
        }

    }
}


mainMenu
