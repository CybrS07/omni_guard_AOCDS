; Extra steps for the Windows installer/uninstaller (electron-builder "nsis.include").
; On uninstall this runs scripts\uninstall-all.ps1, which removes the service, the firewall rules,
; the registry keys and every data folder, so no trace of the app is left on the PC.

!macro customUnInstall
  DetailPrint "Removing all Omni Guard AOCDS data..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\cleanup\uninstall-all.ps1" -Silent -KeepInstallDir'
!macroend
