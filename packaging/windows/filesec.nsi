; NSIS installer for FileSec. The same script builds both the classical and the
; post-quantum installers; the variant is selected with /D defines, e.g.:
;
;   makensis -NOCD /DAPP_NAME="FileSec" /DAPP_EXE="filesec.exe" /DAPP_VERSION="0.4.3" \
;            /DSRC_EXE="target\release\filesec.exe" \
;            /DOUT_FILE="filesec-0.4.3-x86_64-pc-windows-msvc-setup.exe" \
;            /DREG_KEY="FileSec" packaging\windows\filesec.nsi
;
; APP_NAME must differ between the two variants ("FileSec" / "FileSec PQC"):
; InstallDir and the Start Menu shortcut below are both derived from it, so
; sharing a name makes one build overwrite the other's installation.
;
; Run from the repo root with -NOCD: without it makensis switches its working
; directory to the script's folder and the relative SRC_EXE / APP_ICON paths
; (which point under the repo root) would no longer resolve.
;
; A per-user install (no admin) keeps it simple and matches the app's per-user
; data directory.
Unicode true
!include "MUI2.nsh"

!ifndef APP_NAME
  !define APP_NAME "FileSec"
!endif
!ifndef APP_EXE
  !define APP_EXE "filesec.exe"
!endif
!ifndef APP_VERSION
  !define APP_VERSION "0.0.0"
!endif
!ifndef SRC_EXE
  !error "SRC_EXE must be defined (path to the built .exe)"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "FileSec-setup.exe"
!endif
!ifndef REG_KEY
  !define REG_KEY "${APP_NAME}"
!endif
!ifndef APP_ICON
  ; Relative to the repo root (makensis is invoked there with -NOCD). Used for
  ; the installer/uninstaller icon and shipped so the shortcut shows it too.
  !define APP_ICON "crates\filesec-gui\assets\icon\filesec.ico"
!endif

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${REG_KEY}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\${APP_NAME}"
InstallDirRegKey HKCU "Software\${REG_KEY}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
!define MUI_ICON "${APP_ICON}"
!define MUI_UNICON "${APP_ICON}"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File "/oname=${APP_EXE}" "${SRC_EXE}"
  ; The .exe normally carries its own embedded icon (see build.rs), but also
  ; ship the .ico and point the shortcut / Add-Remove entry at it as a
  ; belt-and-suspenders fallback for the case where embedding was skipped (it is
  ; best-effort). /nonfatal keeps a missing/misresolved icon from aborting.
  File "/nonfatal" "/oname=app.ico" "${APP_ICON}"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\app.ico"
  WriteRegStr HKCU "Software\${REG_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\app.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "FileSec contributors"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\app.ico"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${APP_NAME}.lnk"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "Software\${REG_KEY}"
SectionEnd
