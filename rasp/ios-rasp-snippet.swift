//
//  freeRASP (Talsec) — iOS integration snippet for workshop
//  Paste into iGoat-Swift `AppDelegate.swift` and add `freeRASP-iOS` via SPM:
//    https://github.com/talsec/Free-RASP-iOS
//
//  Reference: https://www.talsec.app/freerasp-in-app-protection-security-talsec
//

import UIKit
import TalsecRuntime

@main
class AppDelegate: UIResponder, UIApplicationDelegate, TalsecReactionDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {

        let config = TalsecConfig(
            appBundleIds: ["org.owasp.iGoat-Swift"],
            appTeamId: "REPLACE_TEAM_ID",
            watcherMailAddress: "secops@example.com",
            isProd: true
        )

        Talsec.start(config: config)
        Talsec.shared.delegate = self
        return true
    }

    // MARK: - TalsecReactionDelegate

    func debuggerDetected()      { reactToThreat("debugger") }
    func simulatorDetected()     { reactToThreat("simulator") }
    func jailbreakDetected()     { reactToThreat("jailbreak") }
    func runtimeManipulationDetected() { reactToThreat("hooking/frida") }
    func passcodeDetected()      { reactToThreat("no-device-passcode") }
    func deviceBindingDetected() { reactToThreat("device-rebind") }
    func unofficialStoreDetected()     { reactToThreat("sideloaded") }

    private func reactToThreat(_ kind: String) {
        // Workshop reaction — log, kill session, then terminate.
        NSLog("[freeRASP] threat: \(kind) — terminating session")
        // Real apps: rotate session token, lock account, notify backend.
        exit(0)
    }
}
