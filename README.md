# DevGuard

**Android Runtime Security Inspector** &nbsp;·&nbsp; `v1.5.0` &nbsp;·&nbsp; `minSdk 28 (Android 9+)`

DevGuard is a lightweight Android app that performs real-time security inspection of the device environment. It detects emulators, root/jailbreak modifications, active hooking frameworks, and app integrity issues using a **three-layer detection architecture** that is resistant to single-layer evasion.

---

## Features

### Detection Categories

| Category | What's Detected |
|---|---|
| **Emulator** | AVD, Genymotion, BlueStacks, NoxPlayer, build prop anomalies, hardware identifier spoofing |
| **Root** | Magisk, SuperSU, su binaries, root app packages, mount namespace anomalies |
| **Debug & Hooking** | Xposed/LSPosed framework, Frida server/gadget, debugger attachment, developer options |
| **App Integrity** | Signature mismatch, installer verification, APK tampering indicators |

### Three-Layer Detection Architecture

```
JAVA    (Android API)  ── hookable by Xposed / LSPosed
  ↓
JNI     (C++ / libc)   ── hookable by Frida / Dobby inline patch
  ↓
SYSCALL (kernel)       ── only bypassable at kernel level
```

Cross-layer **deduplication** prevents score inflation: the same underlying fact detected across multiple layers counts once (max weight) plus a small corroboration bonus, not multiple times independently.

**Mismatch signals** — when layers disagree on the same fact — indicate active in-process evasion. These bypass category caps and escalate the risk level to `COMPROMISED`.

### Risk Scoring

Normalized **0–100** score with per-category caps to prevent any single category from dominating.

| Score | Risk Level | Meaning |
|---|---|---|
| 0–2 | `CLEAN` | No suspicious signals |
| 3–10 | `LOW RISK` | Minor signals detected |
| 11–23 | `SUSPICIOUS` | Risk signals present |
| 24–59 | `HIGH RISK` | Rooted or heavily modified device |
| ≥ 60 | `COMPROMISED` | Severely modified environment |
| Mismatch + score ≥ 20 | `COMPROMISED` | Active evasion detected |
| ≥ 5 emulator signals | `EMULATOR` | Likely an emulator |

---

## Tech Stack

| | |
|---|---|
| Language | Kotlin |
| UI | Jetpack Compose + Material 3 |
| Native layer | C++17 via JNI + CMake |
| Architecture | ViewModel + Coroutines (parallel `async/await` scan) |
| Min SDK | 28 (Android 9 Pie) |
| Target SDK | 36 |
| ABI | `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` |

---

## Build

Standard Android Gradle build. No external API keys or secrets required.

```bash
# Debug build
./gradlew assembleDebug

# Release build (requires signing config)
./gradlew assembleRelease
```

> Release signing is intentionally not committed. Configure your own `signingConfigs` block in `app/build.gradle.kts` or pass credentials via environment variables / CI secrets.

---

## Project Structure

```
app/src/main/
├── cpp/                              # JNI native layer (C++17)
│   ├── CMakeLists.txt
│   └── devguard_native.cpp
└── java/com/hajunwon/devguard/
    ├── data/
    │   ├── detector/                 # Per-category detectors
    │   │   ├── EmulatorDetector.kt
    │   │   ├── RootDetector.kt
    │   │   ├── DebugDetector.kt
    │   │   ├── IntegrityDetector.kt
    │   │   └── NativeDetector.kt     # JNI bridge
    │   └── model/                    # Signal, RiskLevel, SignalLayer, SignalCategory
    ├── domain/
    │   └── SecurityAnalyzer.kt       # Parallel scan orchestration + scoring algorithm
    └── ui/
        ├── component/                # Reusable Compose components
        ├── screen/                   # Dashboard, DetectionLog, DeviceInfo, Settings, Raw
        ├── viewmodel/                # SecurityViewModel
        ├── theme/                    # Material 3 theme + SecurityColors
        └── LanguageManager.kt        # KO/EN runtime language switching
```

---

## Localization

The app supports **Korean** (default) and **English**, switchable at runtime from the Settings screen. Detection signal text is intentionally kept raw/untranslated for technical accuracy.

---

## Security Notes

- This app is a **diagnostic tool** — it reads device state but does not modify it.
- No data leaves the device; all analysis is performed locally.
- The three-layer approach means an attacker must patch Java, JNI, *and* syscall layers simultaneously to fully evade detection.

---

## License

[MIT](LICENSE) © 2025 hajunwon
