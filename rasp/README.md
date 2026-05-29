# freeRASP (Talsec) integration — workshop snippets

Reference: <https://www.talsec.app/freerasp-in-app-protection-security-talsec>

freeRASP is a runtime application self-protection SDK. It detects root/jailbreak,
hooking frameworks (Frida, Magisk, Cycript), debuggers, emulators, repackaging,
and screen mirroring — at runtime, inside the running app.

## What our pipeline checks

`scripts/rasp-check.py` is invoked by the **RASP** job in
`pr-security-gate.yml`. It verifies:

| Platform | Dependency declared       | SDK imported                       | Initialized            |
| -------- | ------------------------- | ---------------------------------- | ---------------------- |
| iOS      | `freeRASP-iOS` in Podfile/SPM | `import TalsecRuntime`         | `Talsec.start(...)`    |
| Android  | `com.aheaditec.freeraspandroid:freeraspandroid` in Gradle | `com.aheaditec.talsec.security` | `Talsec.start(...)`    |

Missing dependency → **High**. Missing initialization call → **Critical**
(merge blocked).

## Demo flow

1. Trainer pushes the vulnerable PR — RASP job fails (Critical: not initialized).
2. Trainer pastes `ios-rasp-snippet.swift` / `android-rasp-snippet.kt` into the
   forked iGoat / DIVA app's entry point.
3. Trainer commits — RASP job passes, sticky comment updates, gate unblocks.
