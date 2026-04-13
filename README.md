# 【RELEASE】Akiba Patcher v1 — CoolStar SOF Audio 1.0.5.0 Patcher

Akiba Patcher v1 is a **patcher** for the CoolStar SOF Audio Driver version **1.0.5.0** that **bypass the license verification and hardware ID checks**. If you run this, the driver will load normal and amplifiers will turn on without error.

---

## ～How to use～

Just run the patcher as Administrator. It is automatic after clicking install.

> ⚠️ **Note:** You must turn on Windows test-signing first. If you forget, audio stack will crash probably.

---

## ～For Manual Researchers～

If you don′t want to use the exe and want to edit `csaudiointcsof.sys` by yourself in a hex editor, I share my research here.

Please change these raw file offsets:

| # | Offset | Change to |
|---|--------|-----------|
| 1 | `0x00000148` | `15 38` |
| 2 | `0x000029E8` | `EB` |
| 3 | `0x00003254` | `31 C0 C3` |
| 4 | `0x000061A0` | `B8 01 00 00 00 C3` |

> Please use at your own risk, I don't take responsibility if your Windows breaks.
