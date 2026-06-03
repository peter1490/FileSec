; NSIS installer for FileSec. The same script builds both the classical and the
; post-quantum installers; the variant is selected with /D defines, e.g.:
;
;   makensis /DAPP_NAME="FileSec" /DAPP_EXE="filesec.exe" /DAPP_VERSION="0.1.0" \
;            /DSRC_EXE="target\release\filesec.exe" /DOUT_FILE="FileSec-0.1.0-setup.exe" \
;            /DREG_KEY="FileSec" packaging\windows\filesec.nsi
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

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${REG_KEY}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\${APP_NAME}"
InstallDirRegKey HKCU "Software\${REG_KEY}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
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
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "Software\${REG_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "FileSec contributors"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${APP_NAME}.lnk"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "Software\${REG_KEY}"
SectionEnd
