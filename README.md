<picture>
  <source media="(max-width: 600px)" srcset="https://github.com/user-attachments/assets/584ba62f-c6fc-4c63-9fe9-7cdbbfc54580">
  <img src="https://github.com/user-attachments/assets/08e33064-8ba2-4ab4-8a48-85b4abbd55ec" alt="dllium_banner" style="max-width:100%; height:auto;">
</picture>

<h1 align="center">Modern DLL Injection Made Simple</h1>
<p align="center">
  Advanced DLL Injection for Research & Development





<p align="center">
A lightweight and modern DLL injection tool designed for educational use,
software research, and controlled testing environments.
Built for performance, precision, and simplicity.
</p>


## How It Works

**DLLium** is a high-performance, stealth-oriented DLL injector for Windows, built with reliability and modern design in mind.

It leverages advanced **Manual Mapping** techniques to bypass traditional detection mechanisms — such as those that monitor LoadLibrary calls — by manually loading the PE image directly into the target process’s memory.

Instead of relying on standard Windows loading routines, DLLium maps the DLL into memory step by step, resolves imports, applies relocations, and initializes the module manually. This approach significantly reduces its visibility to conventional monitoring tools.

Built with a native **Win32 C++ backend** and a modern, responsive GUI, DLLium provides developers and security researchers with a powerful solution for process instrumentation and advanced memory manipulation.



<img width="986" height="553" alt="image" src="https://github.com/user-attachments/assets/312c7816-4aa6-490e-8c52-0d0540caf67c" />



## Injection methods
### 1. Manual Mapping

A custom-built engine that maps the DLL directly into memory. It handles:

- **PE Header Parsing**  
  Correctly interprets DOS and NT headers.

- **Section Mapping**  
  Maps individual sections with their respective permissions.

- **Import Resolution**  
  Manually resolves the IAT (*Import Address Table*) using custom remote function lookups.

- **Relocation Handling**  
  Supports delta relocation for both `IMAGE_REL_BASED_DIR64` and `IMAGE_REL_BASED_HIGHLOW`.

- **TLS Callbacks**  
  Executes Thread Local Storage callbacks to ensure full DLL compatibility.

- **Shellcode Execution**  
  Uses a universal shellcode stub to initialize the DLL entry point remotely.

### 2. LoadLibrary

Provides a classic injection method for standard testing and maximum compatibility.


## Stealth & Safety
LDR Bypass: Since manual mapping doesn't use the standard Windows loader, the injected module does not appearing in the InLoadOrderModuleList, making it invisible to many basic anti-cheats and monitors.


## Why is it flagged by Antivirus? (False Positives)
### It is common for DLL Injectors to be flagged as "Potentially Unwanted Programs" (PUP) or even "Malware" by Windows Defender and other antivirus software. This happens for several technical reasons:
- Process Manipulation: DLLium uses low-level Windows APIs (OpenProcess, VirtualAllocEx, WriteProcessMemory) to interact with other running programs. These are the same techniques used by some malware to hide their code.
- Manual Mapping: Our stealth engine bypasses the standard Windows loader. Heuristic engines often flag the use of custom shellcode as suspicious behavior.
- No Digital Signature: This project is unsigned. Antivirus software is naturally suspicious of executable files that do not come from a verified company.


## How to download?
To get the latest compiled version of DLLium, simply follow these steps:
- Go to the [Releases](https://github.com/Paxai/DLLium/releases/tag/v1.0.0) section on the right side of this page.
- Download the latest DLLium.exe file.
- Run as Administrator to ensure the injector has permission to access other processes.

## Everything in this project is Open Source. You can review every line of code to verify its safety.
If you don't trust pre-compiled binaries, we highly recommend building the project from the source code. It only takes a minute:
- **Install Visual Studio**: Download and install [Visual Studio 2022](https://visualstudio.microsoft.com/vs/) (Community version is free). Make sure to check the "Desktop development with C++" workload during installation.
- Clone/Download: Download this repository as a ZIP file and extract it to a folder.
- Open Project: Double-click the `ManualMapping.sln` file to open it in Visual Studio.
- Set Configuration:
  - Change the build mode from Debug to Release.
  - Change the architecture to x64 (or x86 depending on your target).
- Build: Go to the top menu, click Build -> Build Solution (or press Ctrl+Shift+B).
- Locate EXE: Your freshly compiled, safe executable will be in the /x64/Release/ folder.


#

> [!CAUTION]
> This DLL Injector is intended for **educational and research purposes only**.
> Do not use this tool on third-party software, systems, or services without explicit authorization.
> The author is not responsible for any misuse, damages, legal consequences, or losses.
> Use at your own risk.
