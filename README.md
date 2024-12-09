# Tiny11 Builder - A PowerShell script to build a debloated Windows 11 image

You can use it on any Windows 11 release (not just a specific build), as well as any language or architecture.

Since it's written in PowerShell, you need to set the execution policy to `Unrestricted`, so that you can run the script.
If you haven't done this before, make sure to run `Set-ExecutionPolicy unrestricted` as an administrator in PowerShell before running the script, otherwise it'll just crash.

The main goal is to only use Microsoft utilities like DISM, avoiding external tools.
The only executable included is **oscdimg.exe**, which is provided in the Windows ADK and it's used to create bootable ISO images.
Also included is an unattended answer file, which is used to bypass the Microsoft Account on OOBE and to deploy the image with the `/compact` flag.
It's open-source, **so feel free to add or remove anything you want!** Feedback is also much appreciated.

Instructions:

1. Download Windows 11 from the Microsoft website (<https://microsoft.com/software-download/windows11>)
2. Mount the downloaded ISO image using Windows Explorer.
3. Select the drive letter where the image is mounted (only the letter, no colon (:))
4. Select the SKU that you want the image to be based on.
5. When the image is completed, you'll see it in the folder where the script was extracted, with the name tiny11.iso

# What is removed:

- Clipchamp
- News
- Weather
- Xbox (although Xbox Identity provider is still here, so it should be possible to be reinstalled with no issues)
- GetHelp
- GetStarted
- Office Hub
- Solitaire
- PeopleApp
- PowerAutomate
- ToDo
- Alarms
- Mail and Calendar
- Feedback Hub
- Maps
- Sound Recorder
- Your Phone
- QuickAssist
- Internet Explorer
- Tablet PC Math
- Edge
- OneDrive
- Windows Defender (only disabled, can be enabled back if needed)
- Probably forgot something (useless stuff anyways)

**You have to update WinGet using the Microsoft Store before being able to install any apps with it!**

# Known issues:

1. Although Edge is removed, there are some remnants in the Settings.
You can install any browser using WinGet.
If you want Edge, Copilot, and Web Search back, simply install Edge using WinGet: `winget install edge`.
