@echo off
:: Check for admin rights
openfiles >nul 2>&1 || (echo Please run this script as Administrator! & pause & exit /b)

:: =================== Microsoft-Fondler Script ===================
:: Thank you to infradragon for the original script.
:: Edited by Matthew.

:: =================== Script Setup & Elevation ===================
@setlocal DisableDelayedExpansion

:: Re-launch the script with x64 process if it was initiated by x86 process on x64 bit Windows
:: or with ARM64 process if it was initiated by x86/ARM32 process on ARM64 Windows

if exist %SystemRoot%\Sysnative\cmd.exe if not defined re1 (
setlocal EnableDelayedExpansion
start %SystemRoot%\Sysnative\cmd.exe /c ""!_cmdf!" %* re1"
exit /b
)

:: Re-launch the script with ARM32 process if it was initiated by x64 process on ARM64 Windows

if exist %SystemRoot%\SysArm32\cmd.exe if %PROCESSOR_ARCHITECTURE%==AMD64 if not defined re2 (
setlocal EnableDelayedExpansion
start %SystemRoot%\SysArm32\cmd.exe /c ""!_cmdf!" %* re2"
exit /b
)

cls
color 07
title  Microsoft-Fondler

setlocal EnableDelayedExpansion

::========================================================================================================================================

:: =================== User Prompts ===================
cls
echo Device class:
echo [1] Non-battery
echo [2] Battery
set /p "dclass=: "

echo User level:
echo [1] Sysadmin
echo [2] Consumer
set /p "uclass=: "

:: =================== Progress Logging ===================
set LOGFILE=%~dp0fondler_log.txt
if exist "%LOGFILE%" del "%LOGFILE%"
echo --- Microsoft-Fondler Script Log --- > "%LOGFILE%"

:: =================== Bloatware/App Removal ===================
echo Removing Microsoft Edge... >> "%LOGFILE%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://gist.github.com/ave9858/c3451d9f452389ac7607c99d45edecc6/raw/UninstallEdge.ps1 | iex" >> "%LOGFILE%" 2>&1

:: Disable cortana (not present anyways on modern windows)
echo Disabling Cortana... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaInAAD" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Cortana. >> "%LOGFILE%"

:: Disable web and location-based search
echo Disabling web and location-based search... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling web and location-based search. >> "%LOGFILE%"

:: Remove search box/search icon from taskbar and prevent microsoft from randomly putting it back
echo Removing search box and icon from taskbar... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "SearchBoxDisabledReason" /t REG_SZ /d "FromServer" /f 2>nul
echo Finished removing search box and icon from taskbar. >> "%LOGFILE%"

:: Remove search highlights
echo Removing search highlights... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished removing search highlights. >> "%LOGFILE%"

:: Disable Windows Spotlight and ads on lock screen 
echo Disabling Windows Spotlight and ads on lock screen... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "LockScreenOverlaysDisabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanelt" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Windows Spotlight and ads on lock screen. >> "%LOGFILE%"

:: Disable about this wallpaper icon on the desktop
echo Disabling about this wallpaper icon on the desktop... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling about this wallpaper icon on the desktop. >> "%LOGFILE%"

:: Disable lock screen wallpaper slideshow
echo Disabling lock screen wallpaper slideshow... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling lock screen wallpaper slideshow. >> "%LOGFILE%"

:: Set default wallpaper
:: reg add "HKCU\Control Panel\Desktop" /v "WallPaper" /d "C:\WINDOWS\web\wallpaper\Windows\img0.jpg" /t REG_SZ /f

:: Disable find my device
echo Disabling Find My Device... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Find My Device. >> "%LOGFILE%"

:: Disable advertising IDs for interest-based advertising
echo Disabling advertising IDs... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling advertising IDs. >> "%LOGFILE%"

:: Don't let websites access locally installed language list
echo Preventing websites from accessing language list... >> "%LOGFILE%"
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f 2>nul
echo Finished preventing websites from accessing language list. >> "%LOGFILE%"

:: Disable Windows tips 
echo Disabling Windows tips... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Windows tips. >> "%LOGFILE%"

:: Disable smartscreen
echo Disabling SmartScreen... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /d "Anywhere" /t REG_SZ /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 2>nul
echo Finished disabling SmartScreen. >> "%LOGFILE%"

:: Disable switching to secure desktop during UAC prompt (grayed out background)
echo Disabling secure desktop for UAC... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling secure desktop for UAC. >> "%LOGFILE%"

:: Disable defender nag notifications
echo Disabling Defender nag notifications... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Defender nag notifications. >> "%LOGFILE%"

:: Remove "Scan with Microsoft Defender" from context menu
echo Removing "Scan with Microsoft Defender" from context menu... >> "%LOGFILE%"
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f 2>nul
reg delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f 2>nul
echo Finished removing "Scan with Microsoft Defender" from context menu. >> "%LOGFILE%"

:: Remove "Cast to device" from context menu
echo Removing "Cast to device" from context menu... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "" /f 2>nul
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "" /f 2>nul
echo Finished removing "Cast to device" from context menu. >> "%LOGFILE%"

:: Remove "Troubleshoot compatibility" from context menu
echo Removing "Troubleshoot compatibility" from context menu... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f 2>nul
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f 2>nul
echo Finished removing "Troubleshoot compatibility" from context menu. >> "%LOGFILE%"

:: Remove "Include in Library" from context menu
echo Removing "Include in Library" from context menu... >> "%LOGFILE%"
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" /f 2>nul
echo Finished removing "Include in Library" from context menu. >> "%LOGFILE%"

:: Remove bitmap (.bmp) and rtf option from new context menu
echo Removing bitmap and rtf options from new context menu... >> "%LOGFILE%"
reg delete "HKCR\.bmp\ShellNew" /f 2>nul
reg delete "HKCR\.rtf\ShellNew" /f 2>nul
echo Finished removing bitmap and rtf options from new context menu. >> "%LOGFILE%"

:: Remove modern share sheet from context menu
echo Removing modern share sheet from context menu... >> "%LOGFILE%"
reg delete "HKCR\*\shellex\ContextMenuHandlers\ModernSharing" /f 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing" /f 2>nul
echo Finished removing modern share sheet from context menu. >> "%LOGFILE%"

:: Remove Google Drive FS context menu items
echo Removing Google Drive FS context menu items... >> "%LOGFILE%"
reg delete "HKEY_CLASSES_ROOT\.gdoc\ShellNew" /f 2>nul
reg delete "HKEY_CLASSES_ROOT\.gsheet\ShellNew" /f 2>nul
reg delete "HKEY_CLASSES_ROOT\.gslides\ShellNew" /f 2>nul
reg delete "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\GDContextMenu" /f 2>nul
reg delete "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\GDContextMenu" /f 2>nul
reg delete "HKEY_CLASSES_ROOT\lnkfile\shellex\ContextMenuHandlers\GDContextMenu" /f 2>nul
echo Finished removing Google Drive FS context menu items. >> "%LOGFILE%"

:: Don't automatically connect to open hotspots
echo Preventing automatic connection to open hotspots... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f 2>nul
echo Finished preventing automatic connection to open hotspots. >> "%LOGFILE%"

:: Prevent Kerberos from using DES or RC4
echo Preventing Kerberos from using DES or RC4... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d 2147483640 /f 2>nul
echo Finished preventing Kerberos from using DES or RC4. >> "%LOGFILE%"

:: Cipher suites preference order
echo Setting cipher suites preference order... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "Functions" /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /t REG_SZ /f
echo Finished setting cipher suites preference order. >> "%LOGFILE%"

:: Encrypt and sign outgoing secure channel traffic when possible
echo Encrypting and signing outgoing secure channel traffic... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "SealSecureChannel" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "SignSecureChannel" /t REG_DWORD /d 1 /f 2>nul
echo Finished encrypting and signing outgoing secure channel traffic. >> "%LOGFILE%"

:: stuff
echo Disabling various Microsoft consumer features... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202913Enabled" /t REG_DWORD /d 0 /f 2>nul 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202914Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280797Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280811Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280812Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280813Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280814Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280815Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280810Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280817Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310091Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310092Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310094Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314558Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314562Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314566Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314567Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338380Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338381Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338382Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338386Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-346480Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-346481Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353695Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353697Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353699Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000044Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000045Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000105Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000106Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000161Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000162Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000163Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000164Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000165Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000166Enabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling various Microsoft consumer features. >> "%LOGFILE%"

:: Disable suggested settings 
echo Disabling suggested settings... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling suggested settings. >> "%LOGFILE%"

:: Disable online tips in settings
echo Disabling online tips in settings... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowOnlineTips" /v "value" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling online tips in settings. >> "%LOGFILE%"

:: Disable Aero shake
echo Disabling Aero shake... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Aero shake. >> "%LOGFILE%"

:: Disable OneDrive ads in explorer
echo Disabling OneDrive ads in explorer... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling OneDrive ads in explorer. >> "%LOGFILE%"

:: Disable start menu suggested apps 
echo Disabling start menu suggested apps... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling start menu suggested apps. >> "%LOGFILE%"

:: Disable start menu suggested websites
echo Disabling start menu suggested websites... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecommendedPersonalizedSites" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling start menu suggested websites. >> "%LOGFILE%"

:: Disallow automatic app installs and app suggestions (must be applied pre-install or it will only apply for new users and windows updates)
echo Disallowing automatic app installs and app suggestions... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f 2>nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f 2>nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f 2>nul
echo Finished disallowing automatic app installs and app suggestions. >> "%LOGFILE%"

:: Disable the "Let's finish setting up your device" nag screen
echo Disabling "Let's finish setting up your device" nag screen... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /d 1 /f 2>nul
echo Finished disabling "Let's finish setting up your device" nag screen. >> "%LOGFILE%"

:: Disable Windows 10 welcome page 
echo Disabling Windows 10 welcome page... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Windows 10 welcome page. >> "%LOGFILE%"

:: Disable A/B testing
echo Disabling A/B testing... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "Value" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling A/B testing. >> "%LOGFILE%"

:: Stop CDM changing its settings on update
echo Stopping CDM from changing its settings on update... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d 0 /f 2>nul
echo Finished stopping CDM from changing its settings on update. >> "%LOGFILE%"

:: Show hidden files and file extensions
echo Showing hidden files and file extensions... >> "%LOGFILE%"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f 2>nul
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ""ShowSuperHidden" /t REG_DWORD /d 1 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ""ShowSuperHidden" /t REG_DWORD /d 1 /f
echo Finished showing hidden files and file extensions. >> "%LOGFILE%"

:: Don't automatically download Microsoft Store updates
echo Preventing automatic download of Microsoft Store updates... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f 2>nul
echo Finished preventing automatic download of Microsoft Store updates. >> "%LOGFILE%"

:: Disable Windows settings syncing over your Microsoft account
echo Disabling Windows settings syncing... >> "%LOGFILE%"
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Windows settings syncing. >> "%LOGFILE%"

:: Turn desktop wallpaper encoding quality to maximum, although it still looks like garbage because you cant turn off the chroma subsampling (i hate windows if you cant tell already)
echo Setting desktop wallpaper encoding quality to maximum... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f 2>nul
echo Finished setting desktop wallpaper encoding quality to maximum. >> "%LOGFILE%"

:: Don't show network discoverable popup
echo Disabling network discoverable popup... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f 2>nul
echo Finished disabling network discoverable popup. >> "%LOGFILE%"

:: Trade throughput for latency (to be tested further later, valid values 1-70)
echo Trading throughput for latency... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 10 /f 2>nul
echo Finished trading throughput for latency. >> "%LOGFILE%"

:: Forcefully close all apps on shutdown (after the timeout expires)
echo Forcing close all apps on shutdown... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /d "1" /t REG_SZ /f 2>nul
echo Finished forcing close all apps on shutdown. >> "%LOGFILE%"

:: Disable context menu delay
echo Disabling context menu delay... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /d "0" /t REG_SZ /f 2>nul
echo Finished disabling context menu delay. >> "%LOGFILE%"

:: Disable mouse hover info delay
echo Disabling mouse hover info delay... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Desktop" /v "MouseHoverTime" /d "0" /t REG_SZ /f 2>nul
echo Finished disabling mouse hover info delay. >> "%LOGFILE%"

:: Show full context menu even with more than 15 items
echo Showing full context menu even with more than 15 items... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "MultipleInvokePromptMinimum" /t REG_DWORD /d 255 /f 2>nul
echo Finished showing full context menu even with more than 15 items. >> "%LOGFILE%"

:: Always show more details during file transfer
echo Always showing more details during file transfer... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d 1 /f 2>nul
echo Finished always showing more details during file transfer. >> "%LOGFILE%"

:: Disable Windows ink workspace
echo Disabling Windows ink workspace... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Windows ink workspace. >> "%LOGFILE%"

:: Disable widgets and remove icon on taskbar (and news and intrests on Windows 10)
echo Disabling widgets and removing icon on taskbar... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling widgets and removing icon on taskbar. >> "%LOGFILE%"

:: Hide task view on taskbar
echo Hiding task view on taskbar... >> "%LOGFILE%"
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\AllUpView" /v "Enabled" /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f 2>nul
echo Finished hiding task view on taskbar. >> "%LOGFILE%"

:: Hide Meet Now on taskbar
echo Hiding Meet Now on taskbar... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f 2>nul
echo Finished hiding Meet Now on taskbar. >> "%LOGFILE%"

:: Disable desktop peek on taskbar
echo Disabling desktop peek on taskbar... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisablePreviewDesktop" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling desktop peek on taskbar. >> "%LOGFILE%"

:: Disable Windows Chat on taskbar
echo Disabling Windows Chat on taskbar... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Communications" /v "Capabilities" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Windows Chat on taskbar. >> "%LOGFILE%"

:: Disable Copilot
echo Disabling Copilot... >> "%LOGFILE%"
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Copilot. >> "%LOGFILE%"

:: Disable Recall
echo Disabling Recall... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Recall. >> "%LOGFILE%"

:: Prevent user from signing into Microsoft account
echo Preventing user from signing into Microsoft account... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoConnectedUser" /t REG_DWORD /d 1 /f 2>nul
echo Finished preventing user from signing into Microsoft account. >> "%LOGFILE%"

:: Don't prompt to "fix" usb devices
echo Disabling "fix" usb device prompt... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Shell\USB" /v "NotifyOnUsbErrors" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling "fix" usb device prompt. >> "%LOGFILE%"

:: Disable autoplay/autorun for removable drives
echo Disabling autoplay/autorun for removable drives... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0xff /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0xff /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate" /v "MSTakeNoAction" /t REG_NONE /d "" /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" /v "MSTakeNoAction" /t REG_NONE /d "" /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival" /v "MSTakeNoAction" /t REG_NONE /d "" /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival" /v "MSTakeNoAction" /t REG_NONE /d "" /f 2>nul
echo Finished disabling autoplay/autorun for removable drives. >> "%LOGFILE%"

:: Turn off cloud clipboard
echo Turning off cloud clipboard... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d 0 /f 2>nul
echo Finished turning off cloud clipboard. >> "%LOGFILE%"

:: Disable "Tailored Experiences" with diagnostic data
echo Disabling "Tailored Experiences" with diagnostic data... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling "Tailored Experiences" with diagnostic data. >> "%LOGFILE%"

:: Disable spelling data collection
echo Disabling spelling data collection... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling spelling data collection. >> "%LOGFILE%"

:: Disable "continuing experiences on other devices" (also used for data collection)
echo Disabling "continuing experiences on other devices"... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v "BluetoothLastDisabledNearShare" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling "continuing experiences on other devices". >> "%LOGFILE%"

:: Turn off telemetry
echo Turning off telemetry... >> "%LOGFILE%"
sc stop DiagTrack
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableOneSettingsDownloads" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "MiniTraceSlotEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry" /v "Value" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled" /v "Value" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell\\TelemetryID" /v TelemetryID /t REG_SZ /d 0000000000000000 /f 2>nul
echo Finished turning off telemetry. >> "%LOGFILE%"

:: Disable Customer Experience Improvement Program (more telemetry)
echo Disabling Customer Experience Improvement Program... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f 2>nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
echo Finished disabling Customer Experience Improvement Program. >> "%LOGFILE%"

:: Disable Microsoft Office telemetry
echo Disabling Microsoft Office telemetry... >> "%LOGFILE%"
reg add "HKCU\Software\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Policies\Microsoft\office\common\clienttelemetry" /v "sendtelemetry" /t REG_DWORD /d 3 /f 2>nul
schtasks /change /TN "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
echo Finished disabling Microsoft Office telemetry. >> "%LOGFILE%"

:: Disable Sign-in button at the top of office apps
echo Disabling Sign-in button in Office apps... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Office\16.0\Common\SignIn" /v "SignInOptions" /t REG_DWORD /d 3 /f 2>nul
echo Finished disabling Sign-in button in Office apps. >> "%LOGFILE%"

:: Disable Activity Feed in Task View (it's an online feature)
echo Disabling Activity Feed in Task View... >> "%LOGFILE%"
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Activity Feed in Task View. >> "%LOGFILE%"

:: Disable app crash telemetry (goes to Microsoft, not app developers)
echo Disabling app crash telemetry... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "DisableWerReporting" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling app crash telemetry. >> "%LOGFILE%"

:: Disable Device Health Attestation Monitoring and Reporting from checking for secure boot, TPM, bitlocker, etc.
echo Disabling Device Health Attestation Monitoring and Reporting... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Device Health Attestation Monitoring and Reporting. >> "%LOGFILE%"

:: Disable tracking of app performance
echo Disabling tracking of app performance... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnable" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling tracking of app performance. >> "%LOGFILE%"

:: Disable Program Compatibility Assistant telemetry (needed for rockstar games launcher)
echo Disabling Program Compatibility Assistant telemetry... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Program Compatibility Assistant telemetry. >> "%LOGFILE%"

:: Disable Smart App Control 
echo Disabling Smart App Control... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Smart App Control. >> "%LOGFILE%"

:: Turn off location servies and location history
echo Turning off location services and history... >> "%LOGFILE%"
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v "Location" /t REG_SZ /d "Deny" /f 2>nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t REG_MULTI_SZ /d "\0" /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t REG_MULTI_SZ /d "\0" /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t REG_MULTI_SZ /d "\0" /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f 2>nul
echo Finished turning off location services and history. >> "%LOGFILE%"

:: Disable human presence tracking
echo Disabling human presence tracking... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence" /t "REG_DWORD" /d 2 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence_UserInControlOfTheseApps" /t REG_MULTI_SZ /d "\0" /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence_ForceAllowTheseApps" /t REG_MULTI_SZ /d "\0" /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence_ForceDenyTheseApps" /t REG_MULTI_SZ /d "\0" /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanPresence" /v "Value" /t REG_SZ /d "Deny" /f 2>nul
echo Finished disabling human presence tracking. >> "%LOGFILE%"

:: Disable cameras on lock screen
echo Disabling cameras on lock screen... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling cameras on lock screen. >> "%LOGFILE%"

:: Disable storing password in memory in cleartext
echo Disabling storing password in memory in cleartext... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling storing password in memory in cleartext. >> "%LOGFILE%"

:: Require administrator to install printer drivers
echo Requiring administrator to install printer drivers... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v "AddPrinterDrivers" /t REG_DWORD /d 1 /f 2>nul
echo Finished requiring administrator to install printer drivers. >> "%LOGFILE%"

:: Prevent DevHome from being installed via WU
echo Preventing DevHome from being installed via Windows Update... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /v "workCompleted" /t REG_DWORD /d 1 /f 2>nul
echo Finished preventing DevHome from being installed via Windows Update. >> "%LOGFILE%"

:: Prevent Outlook from being installed via WU
echo Preventing Outlook from being installed via Windows Update... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /v "workCompleted" /t REG_DWORD /d 1 /f 2>nul
echo Finished preventing Outlook from being installed via Windows Update. >> "%LOGFILE%"

:: Disable Windows Update restart notifications
echo Disabling Windows Update restart notifications... >> "%LOGFILE%"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartNotificationDisable" /t REG_DWORD /d 1 /f 2>nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "RestartNotificationsAllowed2" /t REG_DWORD /d 0 /f 2>nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetUpdateNotificationLevel" /t REG_DWORD /d 2 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAUAsDefaultShutdownOption" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "HideMCTLink" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Windows Update restart notifications. >> "%LOGFILE%"

:: Disable Windows Update auto restart (unless system is logged out)
echo Disabling Windows Update auto restart... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Windows Update auto restart. >> "%LOGFILE%"

:: Never defer feature or quality updates
echo Never deferring feature or quality updates... >> "%LOGFILE%"
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdates" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdatesPeriodInDays" /t REG_DWORD /d 0 /f 2>nul
echo Finished never deferring feature or quality updates. >> "%LOGFILE%"

:: Disable "Fast Startup"
echo Disabling "Fast Startup"... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling "Fast Startup". >> "%LOGFILE%"

:: Don't update Edge to the chromium version if you have it installed
echo Preventing Edge from updating to the chromium version... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f 2>nul
echo Finished preventing Edge from updating to the chromium version. >> "%LOGFILE%"

:: Remove "Search the store" in the open with context menu
echo Removing "Search the store" from open with context menu... >> "%LOGFILE%"
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f 2>nul
echo Finished removing "Search the store" from open with context menu. >> "%LOGFILE%"

:: Remove the 260 character file path limits
echo Removing 260 character file path limits... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f 2>nul
echo Finished removing 260 character file path limits. >> "%LOGFILE%"

:: Stop Windows Security from bothering you about a Microsoft account
echo Stopping Windows Security from bothering about Microsoft account... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /t REG_DWORD /d 1 /f 2>nul
echo Finished stopping Windows Security from bothering about Microsoft account. >> "%LOGFILE%"

:: Disable Onedrive pre-signin (for users running the script before or during install)
echo Disabling Onedrive pre-signin... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Onedrive pre-signin. >> "%LOGFILE%"

:: Disable Onedrive
echo Disabling Onedrive... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Onedrive. >> "%LOGFILE%"

:: Disable Onedrive user folder intrgration
echo Disabling Onedrive user folder integration... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMBlockOptIn" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling Onedrive user folder integration. >> "%LOGFILE%"

:: Don't show Office files in quick access
echo Hiding Office files in quick access... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d 0 /f 2>nul
echo Finished hiding Office files in quick access. >> "%LOGFILE%"

:: Stop SPP from validating tickets
echo Stopping SPP from validating tickets... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d 1 /f 2>nul
echo Finished stopping SPP from validating tickets. >> "%LOGFILE%"

:: Disable speech and handwriting telemetry when using accessibility features
echo Disabling speech and handwriting telemetry... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling speech and handwriting telemetry. >> "%LOGFILE%"

:: Disable whats basically a keylogger
echo Disabling keylogger... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling keylogger. >> "%LOGFILE%"

:: Disable inking and typing telemetry
echo Disabling inking and typing telemetry... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling inking and typing telemetry. >> "%LOGFILE%"

:: Never show feedback notifications
echo Never showing feedback notifications... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f 2>nul
echo Finished preventing feedback notifications. >> "%LOGFILE%"

:: Don't show miracast quick access tile
echo Hiding miracast quick access tile... >> "%LOGFILE%"
powershell -c "New-ItemProperty -Path 'HKCU:\Control Panel\Quick Actions\Control Center\Unpinned' -Name 'Microsoft.QuickAction.NearShare' -PropertyType None -Value ([byte[]]@()) -Force" >> "%LOGFILE%" 2>&1
echo Finished hiding miracast quick access tile. >> "%LOGFILE%"

:: New boot logo yippee
echo Enabling new boot logo... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\BootControl" /v "BootProgressAnimation" /t REG_DWORD /d 1 /f 2>nul
echo Finished enabling new boot logo. >> "%LOGFILE%"

:: Disable " - Shortcut" text and the end of newly created shortcuts
echo Disabling " - Shortcut" text for new shortcuts... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" /v "ShortcutNameTemplate" /d "%s.lnk" /t REG_SZ /f 2>nul
echo Finished disabling " - Shortcut" text for new shortcuts. >> "%LOGFILE%"

:: Add end task to app's taskbar context menu
echo Adding end task to app's taskbar context menu... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d 1 /f 2>nul
echo Finished adding end task to app's taskbar context menu. >> "%LOGFILE%"

:: Add seconds to the taskbar clock
echo Adding seconds to the taskbar clock... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" /t REG_DWORD /d 1 /f 2>nul
echo Finished adding seconds to the taskbar clock. >> "%LOGFILE%"

:: Make taskbar small
echo Making taskbar small... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSi" /t REG_DWORD /d 0 /f 2>nul
echo Finished making taskbar small. >> "%LOGFILE%"

:: Disable suggested text actions
echo Disabling suggested text actions... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling suggested text actions. >> "%LOGFILE%"

:: Change icon cache maximum size to 32MB
echo Changing icon cache maximum size to 32MB... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "MaxCachedIcons" /t REG_SZ /d "32768" /f 2>nul
echo Finished changing icon cache maximum size to 32MB. >> "%LOGFILE%"

:: Enable taskbar icon cache
echo Enabling taskbar icon cache... >> "%LOGFILE%"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d 1 /f 2>nul
echo Finished enabling taskbar icon cache. >> "%LOGFILE%"

:: Remove edit with Paint 3D file associations
echo Removing Paint 3D file associations... >> "%LOGFILE%"
reg delete "HKCR\SystemFileAssociations\.3mf\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.bmp\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.fbx\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.gif\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.jfif\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.jpe\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.jpeg\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.jpg\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.png\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.tif\Shell\3D Edit" /f 2>nul
reg delete "HKCR\SystemFileAssociations\.tiff\Shell\3D Edit" /f 2>nul
echo Finished removing Paint 3D file associations. >> "%LOGFILE%"

:: Disable automatic appx app archiving
echo Disabling automatic appx app archiving... >> "%LOGFILE%"
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx" /v "AllowAutomaticAppArchiving" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling automatic appx app archiving. >> "%LOGFILE%"

:: Disable associated app icons on thumbnails
echo Disabling associated app icons on thumbnails... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling associated app icons on thumbnails. >> "%LOGFILE%"

:: Disable Game Bar
echo Disabling Game Bar... >> "%LOGFILE%"
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d 3 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Game Bar. >> "%LOGFILE%"

:: Disable Game Bar and also fix the ltsc bug thing with games
echo Disabling Game Bar (LTSC fix)... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling Game Bar (LTSC fix). >> "%LOGFILE%"

:: Windows Search Indexing respects power modes 
echo Configuring Windows Search Indexing to respect power modes... >> "%LOGFILE%"
reg add "HKLM\Software\Microsoft\Windows Search\Gather\Windows\SystemIndex" /v "RespectPowerModes" /t REG_DWORD /d 1 /f 2>nul
echo Finished configuring Windows Search Indexing. >> "%LOGFILE%"

:: Disable SMB bandwidth throttling
echo Disabling SMB bandwidth throttling... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling SMB bandwidth throttling. >> "%LOGFILE%"

:: Disable LLMNR
echo Disabling LLMNR... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f 2>nul
echo Finished disabling LLMNR. >> "%LOGFILE%"

:: Remove "3D Objects" folder
echo Removing "3D Objects" folder... >> "%LOGFILE%"
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f 2>nul
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f 2>nul
del "%USERPROFILE%\3D Objects"
echo Finished removing "3D Objects" folder. >> "%LOGFILE%"

:: Don't track recently and most opened files on remote locations
echo Stopping tracking of recently and most opened files on remote locations... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoRemoteDestinations" /t REG_DWORD /d 1 /f 2>nul
echo Finished stopping tracking of recently and most opened files on remote locations. >> "%LOGFILE%"

:: Stop explorer from automatically discovering folder content type
echo Stopping explorer from automatically discovering folder content type... >> "%LOGFILE%"
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f 2>nul
echo Finished stopping explorer from automatically discovering folder content type. >> "%LOGFILE%"

:: Enable verbose log in/out and power on/off messages
echo Enabling verbose log in/out and power on/off messages... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "verbosestatus" /t REG_DWORD /d 0 /f 2>nul
echo Finished enabling verbose log in/out and power on/off messages. >> "%LOGFILE%"

:: Disable sticky keys and related key shortcuts
echo Disabling sticky keys and related key shortcuts... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling sticky keys and related key shortcuts. >> "%LOGFILE%"

:: Disable flashes and sounds for sticky keys and other accessibility features
echo Disabling flashes and sounds for accessibility features... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Accessibility" /v "Warning Sounds" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Control Panel\Accessibility" /v "Sound on Activation" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Control Panel\Accessibility\SoundSentry" /v "WindowsEffect" /d "0" /t REG_SZ /f
echo Finished disabling flashes and sounds for accessibility features. >> "%LOGFILE%"

:: Disable win+volume touch accessibility shortcut
echo Disabling win+volume touch accessibility shortcut... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d 0 /f
echo Finished disabling win+volume touch accessibility shortcut. >> "%LOGFILE%"

:: Disable language bar shortcuts
echo Disabling language bar shortcuts... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Input Method\Hot Keys\00000104" /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_DWORD /d 3 /f 2>nul
reg add "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_DWORD /d 3 /f 2>nul
reg add "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_DWORD /d 3 /f 2>nul
echo Finished disabling language bar shortcuts. >> "%LOGFILE%"

:: Disable narrator shortcut
echo Disabling narrator shortcut... >> "%LOGFILE%"
reg add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d 0 /f
echo Finished disabling narrator shortcut. >> "%LOGFILE%"

:: Revert to classic file explorer search
echo Reverting to classic file explorer search... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Classes\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" /ve /d "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" /ve /d "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" /t REG_SZ /f
reg add "HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" /ve /d "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" /t REG_SZ /f
echo Finished reverting to classic file explorer search. >> "%LOGFILE%"

:: Disable explorer check boxes
echo Disabling explorer check boxes... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling explorer check boxes. >> "%LOGFILE%"

:: Explorer home page set to "This PC"
echo Setting explorer home page to "This PC"... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f 2>nul
echo Finished setting explorer home page to "This PC". >> "%LOGFILE%"

:: Do not animate minimizing and maximizing windows
echo Disabling window animation when minimizing and maximizing... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /d "0" /t REG_SZ /f 2>nul
echo Finished disabling window animation when minimizing and maximizing. >> "%LOGFILE%"

:: Allow visual effects settings to apply
echo Allowing visual effects settings to apply... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f 2>nul
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9432078010000000 /f
echo Finished allowing visual effects settings to apply. >> "%LOGFILE%"

:: File association for .pow power plan files
echo Setting file association for .pow power plan files... >> "%LOGFILE%"
reg add "HKCR\powerscheme\DefaultIcon" /ve /d "%windir%\System32\powercpl.dll,1" /t REG_SZ /f
reg add "HKCR\powerscheme\Shell\open\command" /ve /d "powercfg /import \"%1\"" /t REG_SZ /f
reg add "HKCR\.pow" /ve /d "powerscheme" /t REG_SZ /f
reg add "HKCR\.pow" /v "FriendlyTypeName" /d "Power Scheme" /t REG_SZ /f
echo Finished setting file association for .pow power plan files. >> "%LOGFILE%"

:: Do not auto install teams
echo Disabling automatic installation of Teams... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f 2>nul
echo Finished disabling automatic installation of Teams. >> "%LOGFILE%"

:: Disallow anonymous account enumeration
echo Disallowing anonymous account enumeration... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f 2>nul
echo Finished disallowing anonymous account enumeration. >> "%LOGFILE%"

:: Fix random issue where non-removable keyboard layouts are added due to an incorrect auto-detected locale
echo Fixing random keyboard layout issue... >> "%LOGFILE%"
reg delete "HKEY_CURRENT_USER\Control Panel\International\User Profile System Backup" /f
echo Finished fixing random keyboard layout issue. >> "%LOGFILE%"

:: Disable window animation when minimizing and restoring
echo Disabling window animation when minimizing and restoring... >> "%LOGFILE%"
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d 1 /f
echo Finished disabling window animation when minimizing and restoring. >> "%LOGFILE%"

:: Add additional temporary file definitions, parity with Windows Server
echo Adding additional temporary file definitions... >> "%LOGFILE%"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v Folder /t REG_BINARY /d 2520540045004D0025007C002525005700490049004E0044004900520025005C00540065006D0070007C002525005700490049004E0044004900520025005C004C006F00670073007C002525005700490049004E0044004900520025005C0053007900730074006500740065006D00330032005C004C006F006700460069006C00650073007C002525005700490049004E0044004900520025005C0053007900730074006500740065006D00740070000000 /f
echo Finished adding additional temporary file definitions. >> "%LOGFILE%"

:: Network zone configuration parity with Windows Server
echo Configuring network zone settings... >> "%LOGFILE%"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "AutoDetect" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "Flags" /t REG_DWORD /d 67 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "2500" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "Flags" /t REG_DWORD /d 67 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "MinLevel" /t REG_DWORD /d 10500 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A03" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1200" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1400" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1402" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1405" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1407" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1601" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1604" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1606" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1608" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1802" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1803" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1804" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A00" /t REG_DWORD /d 65536 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A02" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A05" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A06" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1C00" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2000" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2100" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2101" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2106" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2300" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2401" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2600" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2701" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2704" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "CurrentLevel" /t REG_DWORD /d 73728 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "MinLevel" /t REG_DWORD /d 73728 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "RecommendedLevel" /t REG_DWORD /d 73728 /f
echo Finished configuring network zone settings. >> "%LOGFILE%"

:: Disable funky office and linkedin keyboard shortcuts
echo Disabling funky office and linkedin keyboard shortcuts... >> "%LOGFILE%"
reg add "HKCU\Software\Classes\ms-officeapp\Shell\Open\Command" /d "rundll32" /t REG_SZ /f
echo Finished disabling funky office and linkedin keyboard shortcuts. >> "%LOGFILE%"

:: Disable memory dump from devices
echo Disabling memory dump from devices... >> "%LOGFILE%"
reg add "HKLM\System\ControlSet001\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d 0 /f
echo Finished disabling memory dump from devices. >> "%LOGFILE%"

:: Dont reduce sound volume in calls
echo Preventing sound volume reduction in calls... >> "%LOGFILE%"
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d 3 /f
echo Finished preventing sound volume reduction in calls. >> "%LOGFILE%"

:: Make control panel godmode
echo Making control panel godmode... >> "%LOGFILE%"
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /ve /d "All Tasks" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /v "InfoTip" /d "View list of all Control Panel tasks" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /v "System.ControlPanel.Category" /d "5" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}\DefaultIcon" /ve /d "%windir%\System32\imageres.dll,-27" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}\Shell\Open\Command" /ve /d "explorer.exe shell:::{ED7BA470-8E54-465E-825C-99712043E01C}" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /ve /d "All Tasks" /t REG_SZ /f
echo Finished making control panel godmode. >> "%LOGFILE%"

:: Drop Windows Platform Binary Tables, which allow hardware to force the loading of software on every boot using an ACPI table
echo Dropping Windows Platform Binary Tables... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableWpbtExecution" /t REG_DWORD /d 1 /f
echo Finished dropping Windows Platform Binary Tables. >> "%LOGFILE%"

:: Network drives over UAC
echo Configuring network drives over UAC... >> "%LOGFILE%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLinkedConnections" /t REG_DWORD /d 1 /f
echo Finished configuring network drives over UAC. >> "%LOGFILE%"

:: Configure kernel panic to dump useful info
echo Configuring kernel panic settings... >> "%LOGFILE%"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d 0 /f
echo Finished configuring kernel panic settings. >> "%LOGFILE%"

:: Configure storage sense to clean temp files every month 
echo Configuring storage sense... >> "%LOGFILE%"
:: Enable storage sense
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 1 /f
:: Enable storage sense morer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 1024 /t REG_DWORD /d 1 /f
:: Run every week
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 2048 /t REG_DWORD /d 7 /f
:: Clean temp files
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 04 /t REG_DWORD /d 1 /f
:: Disable download cleanup
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 32 /t REG_DWORD /d 0 /f
:: Disable OneDrive cleanup
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 02 /t REG_DWORD /d 0 /f
:: Disable OneDrive cleanup (more)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 128 /t REG_DWORD /d 0 /f
:: Cleanup recycle bin
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 08 /t REG_DWORD /d 1 /f
:: Clean recycle bin every month
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 256 /t REG_DWORD /d 30 /f
schtasks /Change /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /ENABLE
echo Finished configuring storage sense. >> "%LOGFILE%"

:: Delay appx autoremoval until after user logon becaus I dont trust Microsoft to do it right
echo Delaying appx autoremoval until after user logon... >> "%LOGFILE%"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\Appx\Applications" /v "NoReRegisterOnUpgrade" /t REG_DWORD /d 1 /f
echo Finished delaying appx autoremoval until after user logon. >> "%LOGFILE%"

:: Telemetry services
echo Disabling telemetry services... >> "%LOGFILE%"
sc config OneSyncSvc start= disabled
sc config TrkWks start= disabled
sc config PcaSvc start= disabled
sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config WerSvc start= disabled
sc config wercplsupport start= disabled
sc config UCPD start= disabled
sc config Telemetry start= disabled
sc config dwmappushservice start= disabled
echo Finished disabling telemetry services. >> "%LOGFILE%"

:: Location services
echo Disabling location services... >> "%LOGFILE%"
sc config lfsvc start= disabled
sc config MapsBroker start= disabled
echo Finished disabling location services. >> "%LOGFILE%"

:: Disable netbios
echo Disabling netbios... >> "%LOGFILE%"
sc config NetBT start= disabled
echo Finished disabling netbios. >> "%LOGFILE%"

:: Configure NTP
echo Configuring NTP... >> "%LOGFILE%"
sc start w32time
w32tm /config /syncfromflags:manual /manualpeerlist:"time.cloudflare.com 0.us.pool.ntp.org 1.us.pool.ntp.org 2.us.pool.ntp.org"
w32tm /config /update
w32tm /resync
echo Finished configuring NTP. >> "%LOGFILE%"

:: Disable powershell core telemetry
echo Disabling PowerShell Core telemetry... >> "%LOGFILE%"
setx POWERSHELL_TELEMETRY_OPTOUT 1
echo Finished disabling PowerShell Core telemetry. >> "%LOGFILE%"

:: Disable .NET CLI telemetry
echo Disabling .NET CLI telemetry... >> "%LOGFILE%"
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
echo Finished disabling .NET CLI telemetry. >> "%LOGFILE%"

:: Delete telemetry service cache
echo Deleting telemetry service cache... >> "%LOGFILE%"
del "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\DiagTrack*" "%ProgramData%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\DiagTrack*" > nul 2>&1
echo Finished deleting telemetry service cache. >> "%LOGFILE%"

:: Set ps1 files to open with powershell (duh)
echo Setting ps1 files to open with PowerShell... >> "%LOGFILE%"
ftype Microsoft.PowerShellScript.1="%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -EP Unrestricted -File "%1" %*
echo Finished setting ps1 files to open with PowerShell. >> "%LOGFILE%"

:: Disable 8dot3 character-length file names on new partitions and strip existing ones on the C drive 
echo Disabling 8dot3 character-length file names... >> "%LOGFILE%"
fsutil 8dot3name strip /f /s /v c:
fsutil behavior set disable8dot3 1
echo Finished disabling 8dot3 character-length file names. >> "%LOGFILE%"

:: Disable last access because its generally useless
echo Disabling last access... >> "%LOGFILE%"
fsutil behavior set disablelastaccess 1
echo Finished disabling last access. >> "%LOGFILE%"

:: Make bootloader use actual screen resolution
echo Configuring bootloader to use actual screen resolution... >> "%LOGFILE%"
bcdedit /set {globalsettings} highestmode true
echo Finished configuring bootloader to use actual screen resolution. >> "%LOGFILE%"

:: Allow pressing f8 during startup for advanced options
echo Allowing F8 during startup for advanced options... >> "%LOGFILE%"
bcdedit /set {bootloadersettings} bootmenupolicy legacy
echo Finished allowing F8 during startup for advanced options. >> "%LOGFILE%"

:: Explicitly set the use of HPET (in bios) and dynamic ticking
echo Configuring HPET and dynamic ticking... >> "%LOGFILE%"
bcdedit /set useplatformtick No
echo Finished configuring HPET and dynamic ticking. >> "%LOGFILE%"

:: Enable hibernation
echo Enabling hibernation... >> "%LOGFILE%"
powercfg /h on
echo Finished enabling hibernation. >> "%LOGFILE%"

:: remove defaultuser0 cuz it sucks
echo Removing defaultuser0... >> "%LOGFILE%"
net user defaultuser0 /delete
echo Finished removing defaultuser0. >> "%LOGFILE%"

:: Uninstall Onedrive 
echo Uninstalling Onedrive... >> "%LOGFILE%"
taskkill /f /im OneDrive.exe > nul 2>&1
for %%a in (
	"%windir%\System32\OneDriveSetup.exe"
	"%windir%\SysWOW64\OneDriveSetup.exe"
) do (
	if exist "%%a" (
		"%%a" /uninstall > nul 2>&1
	)
)

rmdir /q /s "%ProgramData%\Microsoft OneDrive" > nul 2>&1
rmdir /q /s "%LOCALAPPDATA%\Microsoft\OneDrive" > nul 2>&1

for /f "usebackq delims=" %%a in (`dir /b /a:d "%SystemDrive%\Users"`) do (
	rmdir /q /s "%SystemDrive%\Users\%%a\AppData\Local\Microsoft\OneDrive" > nul 2>&1
	rmdir /q /s "%SystemDrive%\Users\%%a\OneDrive" > nul 2>&1
	del /q /f "%SystemDrive%\Users\%%a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" > nul 2>&1
)

for /f "usebackq delims=" %%a in (`reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" ^| findstr /i /c:"OneDrive"`) do reg delete "%%a" /f > nul 2>&1

for /f "tokens=2 delims=\" %%a in ('schtasks /query /fo list /v ^| findstr /c:"\OneDrive Reporting Task" /c:"\OneDrive Standalone Update Task"') do (
	schtasks /delete /tn "%%a" /f > nul 2>&1
)

for /f "usebackq delims=" %%a in (`reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BannerStore" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)
for /f "usebackq delims=" %%a in (`reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)
for /f "usebackq delims=" %%a in (`reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)
for /f "usebackq delims=" %%a in (`reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)

reg add "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Classes\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1

reg delete "HKCU\Environment" /v "OneDrive" /f > nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > nul 2>&1

setlocal enabledelayedexpansion

:: Define the list of appx packages to remove
set packages[1]=ActiproSoftware
set packages[2]=AdobeSystemIncorporated.AdobePhotoshop
set packages[3]=Clipchamp.Clipchamp
set packages[4]=Duolingo
set packages[5]=EclipseManager
set packages[6]=king.com.
set packages[7]=Microsoft.BingFinance
set packages[8]=Microsoft.BingNews
set packages[9]=Microsoft.BingSports
set packages[10]=Microsoft.BingWeather
set packages[11]=Microsoft.GetHelp
set packages[12]=Microsoft.Getstarted
set packages[13]=Microsoft.Office.Sway
set packages[14]=Microsoft.Office.OneNote
set packages[15]=Microsoft.MicrosoftOfficeHub
set packages[16]=Microsoft.MicrosoftSolitaireCollection
set packages[17]=Microsoft.MicrosoftStickyNotes
set packages[18]=Microsoft.MixedReality.Portal
set packages[19]=Microsoft.SkypeApp
set packages[20]=Microsoft.Todo
set packages[21]=Microsoft.WindowsAlarms
set packages[22]=microsoft.windowscommunicationsapps
set packages[23]=Microsoft.WindowsFeedbackHub
set packages[24]=Microsoft.WindowsMaps
set packages[25]=Microsoft.WindowsSoundRecorder
set packages[26]=Microsoft.XboxApp
set packages[27]=Microsoft.Xbox.TCUI
set packages[28]=Microsoft.XboxGameOverlay
set packages[29]=Microsoft.XboxGamingOverlay
set packages[30]=Microsoft.YourPhone
set packages[31]=Microsoft.ZuneMusic
set packages[32]=Microsoft.ZuneVideo100
set packages[33]=Microsoft.Messaging
set packages[34]=MicrosoftCorporationII.MicrosoftFamily
set packages[35]=Microsoft.OutlookForWindows
set packages[36]=MicrosoftCorporationII.QuickAssist
set packages[37]=Microsoft.MicrosoftNotes
set packages[38]=Microsoft.Microsoft3DViewer
set packages[39]=Microsoft.OneConnect
set packages[40]=Microsoft.Print3D
set packages[41]=Microsoft.Services.Store.Engagement
set packages[42]=Microsoft.Wallet
set packages[43]=Microsoft.WindowsSoundRecorder
set packages[44]=Microsoft.WindowsFeedback
set packages[45]=Microsoft.XboxSpeechToTextOverlay
set packages[46]=Microsoft.549981C3F5F10
set packages[47]=netflix
set packages[48]=PandoraMedia
set packages[49]=SpotifyAB.SpotifyMusic
set packages[50]=.Twitter
set packages[51]=Windows.ContactSupport
set packages[52]=Windows.DevHome
set packages[53]=Microsoft.PowerAutomateDesktop
set packages[54]=MSTeams
set packages[55]=msteams
set packages[56]=MicrosoftTeams
set packages[57]=Microsoft.Copilot
set packages[58]=Disney.37853FC22B2CE
:: This is Paint 3D, NOT the real MS Paint
set packages[59]=Microsoft.MSPaint

set count=1

:: Iterate through the elements of the array to calculate its length
:ArrLoop
if defined packages[%count%] (
    set /a count+=1
    GOTO :ArrLoop
)

echo Removing %count% appx packages.

:: Loop through the packages and remove them, and their provisioned counterparts
for /l %%i in (1,1,%count%-1) do (
    set packageName=!packages[%%i]!
    if defined packageName (
        echo Removing installed package: !packageName!
        powershell -Command "Get-AppxPackage *!packageName!* -AllUsers | Remove-AppxPackage"
        echo Removing provisioned package: !packageName!
        powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like '!packageName!'} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }"
    )
)

endlocal

:: Remove legacy internet explorer if it is installed
powershell -Command "Get-WindowsCapability -Online "Browser.InternetExplorer~~~~0.0.11.0" | Remove-WindowsCapability -NoRestart -Online -ErrorAction 'Continue'"

:: Remove Exchange ActiveSync
powershell -Command "Get-WindowsCapability -Online "OneCoreUAP.OneSync~~~~0.0.1.0" | Remove-WindowsCapability -NoRestart -Online -ErrorAction 'Continue'"

:: Remove TPM Diagnostics app
powershell -Command "Get-WindowsCapability -Online "Tpm.TpmDiagnostics~~~~0.0.1.0" | Remove-WindowsCapability -NoRestart -Online -ErrorAction 'Continue'"

:: Enable DirectPlay (for games)
powershell -Command "Enable-WindowsOptionalFeature -FeatureName 'DirectPlay' -NoRestart -All -Online"

:: Remove defaultuser0 (not needed after installation)
net user defaultuser0 /delete

:: Rebuild performance counters
lodctr /r
lodctr /r
winmgmt /resyncperf

:: Re-register start menu (fixes random error)
powershell -Command "Stop-Process -Name 'StartMenuExperienceHost' -Force"
powershell -Command "Get-AppxPackage -AllUsers Microsoft.Windows.ShellExperienceHost | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register '$($_.InstallLocation)\AppXManifest.xml'}"

:: Cleanup component store
dism /Online  /Cleanup-Image /StartComponentCleanup

:: Enable TCP BBR2 congestion algorithm (will only work on Windows 11, will throw errors otherwise)
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
netsh int tcp set supplemental Template=Compat CongestionProvider=CUBIC
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2

:: =================== End of Script ===================
:FondlerEnd
echo:
echo Press any key to exit...
echo See fondler_log.txt for details and errors. >> "%LOGFILE%"
pause >nul
exit /b
