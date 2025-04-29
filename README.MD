# 7 Days to Die Anti-Cheat Prototype

**A simple prototype DLL for 7 Days to Die**

## Overview
This project is a minimal proof-of-concept anti-cheat for the game *7 Days to Die*. It hooks XInput by proxying (hijacking) `xinput1_3.dll` and performs the following:

- **Detects known cheat executables and windows** by scanning running processes and visible window titles.
- **Terminates detected cheat processes** and then closes the game automatically after a 5-second countdown.
- **Provides a `verify` command** (typing `V-E-R-I-F-Y`) to display a test message box, confirming the DLL is loaded.

> **Note:** This is just a starting point. It is not production-ready and should be extended for real-world use.

## Features

- **Explicit detection lists** for popular trainers and cheat engines:
  - WeMod, Cheat Engine, FLiNG trainer, MrAntiFun, PLITCH, UnknownCheats, and more.
  - Exact entries for trainers like "7 Days to Die Early Access Plus 23 Trainer".
- **Generic keyword scanning** for any process containing substrings like `trainer`, `cheat`, `hack`, etc.
- **Window title checks** against known cheat window fragments.
- **Auto-close**: Schedules the game to exit 5 seconds after a cheat is detected, even if the warning dialog is not dismissed.
- **Debug command (`verify`)**: Type `V-E-R-I-F-Y` at any time to pop up a "DLL Verified" message.

![Cheat Engine Detection](https://i.imgur.com/LDHBTEL.png)

## Usage

1. **Build** the project as a 64-bit DLL (release or debug).
2. **Place** the compiled `xinput1_3.dll` in the game folder alongside `7DaysToDie.exe`.
3. **Launch** the game. The anti-cheat monitor thread starts automatically.
4. **Test** by typing `V-E-R-I-F-Y` in-game to confirm the DLL is active.

## Extensions & Modding

This prototype can be extended or integrated into a modlet:

- **DLL enforcement**: Check for the presence of this DLL on the server side or via game scripting. You can grant positive buffs for clients that load the DLL, and negative debuffs (e.g., reduced stamina, damage) for those that don’t.
- **ModInfo.xml**: Use this source to build a proper modlet. Add configuration and hooks in your `ModInfo.xml` to load and verify the DLL at startup.
- **Additional detection mechanisms**: Incorporate signature checking, memory scanning, network validation, or other anti-tamper measures.


> **Disclaimer:** This is a prototype and for educational purposes only. Use at your own risk. Feel free to fork and enhance!

