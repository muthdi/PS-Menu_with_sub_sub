       #Make Your ISO          
       #
#works as designed - no warranty 

     #design : dieter muth    

   #version : V1.0  / 6-2020   

  #YOU NEED TO INSTALL ADK  
      #and run as admin    



pause
cls
#........................Check permissions ......................................

Write-Host "Checking for elevated permissions..."
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Warning "########################################################################################################################"
	Write-Warning "########################################################################################################################"
	Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
	Write-Warning "########################################################################################################################"
	Write-Warning "########################################################################################################################"
	
	exit
}
else
{
	Write-Host "Code is running as administrator - go on executing the script..." -ForegroundColor Green
}

$DISMFile = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe'
If (!(Test-Path $DISMFile)) { Write-Warning "DISM in Windows ADK not found, aborting..."; exit }

#........................INFO for working path......................................

Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "# put in working drive  ex: c:\test   #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
$drive = Read-Host -Prompt 'put in working drive'
if (!(Test-Path -path $drive)) { New-Item -path $drive -ItemType Directory }
if (!(Test-Path -path $drive\iso)) { New-Item -path $drive\iso -ItemType Directory }
if (!(Test-Path -path $drive\mount)) { New-Item -path $drive\mount -ItemType Directory }
if (!(Test-Path -path $drive\setup)) { New-Item -path $drive\setup -ItemType Directory }
if (!(Test-Path -path $drive\upd)) { New-Item -path $drive\upd -ItemType Directory }
cls

Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#  copy your ISO to work \iso         #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
pause
cls
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#  put in ISO name without .iso       #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
$ISOname = Read-Host -Prompt 'put in ISO Name'
cls
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "# copy your updates to work \upd      #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
pause
cls
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "# put in NEW ISO name without .iso    #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
$NewISOname = Read-Host -Prompt 'put in NEW ISO Name'
cls

$ISO = "$drive\iso\$ISOname.iso"

$MountFolder = "$drive\mount"
$RefImageFolder = "$drive\setup"
$TmpImage = "$RefImageFolder\tmp_install.wim"
$RefImage = "$RefImageFolder\new.wim"


# Mount the ISO
Mount-DiskImage -ImagePath $ISO
$ISOImage = Get-DiskImage -ImagePath $ISO | Get-Volume
$ISODrive = [string]$ISOImage.DriveLetter + ":"

$Mount = "$drive\mount"
if (!(Test-Path -path $Mount)) { New-Item -path $Mount -ItemType Directory }
$RefImageFolder = "$drive\RefImageFolder"
if (!(Test-Path -path $RefImageFolder)) { New-Item -path $RefImageFolder -ItemType Directory }
XCopy "$ISODrive\Sources\install.wim" $Mount /Y



do
{
	dism /get-imageinfo /imagefile:"$Mount\install.wim"
	Write-Host "#######################################" -ForegroundColor Green
	Write-Host "#######################################" -ForegroundColor Green
	Write-Host "#         delete index ?        y/n   #" -ForegroundColor Green
	Write-Host "#######################################" -ForegroundColor Green
	Write-Host "#######################################" -ForegroundColor Green
	$delindex = Read-Host -Prompt 'y / n'
	If ($delindex -eq "n") { Break }
	Write-Output "index number ?"
	$index = Read-Host -Prompt 'index'
	Dism /Delete-Image /ImageFile:"$Mount\install.wim" /Index:$index
	dism /get-imageinfo /imagefile:"$Mount\install.wim"
}
until ($delindex -eq "n")
cls

Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#        letÂ´s go one                 #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
pause
cls

#.......................select index ......................................
dism /get-imageinfo /imagefile:"$Mount\install.wim"
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#            mount index              #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
$mountindex = Read-Host -Prompt 'mount index'
cls
#........................ coffee ......................................

Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#      next steps will take time      #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#        so take a coffee             #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#          and let me work            #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
pause
cls

#........................ working ......................................

DISM /Mount-Wim /WimFile:"$Mount\install.wim" /Index:$mountindex /MountDir:$RefImageFolder


#........................ update ......................................

Dism /Image:"$RefImageFolder" /Add-Package /PackagePath:"$drive\upd"

DISM /unmount-Wim /MountDir:$RefImageFolder /commit
DISM /Cleanup-Wim


#........................ create ISO ......................................


if (!(Test-Path -path c:\temp\genISO)) { New-Item -path c:\temp\genISO -ItemType Directory }
if (!(Test-Path -path c:\temp\NEWISO)) { New-Item -path c:\temp\NEWISO -ItemType Directory }
$OSCD = "c:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\"

XCopy "$ISODrive" c:\temp\genISO /E /C /Q /I /Y
XCopy $drive\mount\*.wim c:\temp\genISO\sources\install.wim /Y
cd \

& "c:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\\Oscdimg.exe" -m -u2 -pEF -u1 -udfver102 -bc:\temp\genISO\efi\microsoft\boot\efisys.bin c:\temp\genISO c:\temp\NEWISO\$NewISOname.iso
XCopy c:\temp\NEWISO\*.iso $drive /E /C /Q /I /Y

#........................ cleanup ......................................


rd C:\temp\genISO -Recurse
rd C:\temp\NEWISO -Recurse

Dismount-DiskImage -DevicePath \\.\$ISODrive
cls
#........................ ready ......................................

Write-Host "#######################################" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
Write-Host "#               ready                 #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#            Your ISO is done         #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#    find it in your work folder      #" -ForegroundColor Green
Write-Host "# find your image in your work folder #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#                                     #" -ForegroundColor Green
Write-Host "#         thanks for using            #" -ForegroundColor Green
Write-Host "########   make your ISO   ############" -ForegroundColor Green
Write-Host "#######################################" -ForegroundColor Green
