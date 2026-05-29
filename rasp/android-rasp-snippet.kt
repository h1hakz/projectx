/*
 *  freeRASP (Talsec) — Android integration snippet for workshop
 *  Drop into DIVA's Application class. Add to app/build.gradle:
 *      implementation "com.aheaditec.freeraspandroid:freeraspandroid:13.1.0"
 *
 *  Reference: https://www.talsec.app/freerasp-in-app-protection-security-talsec
 */

package jakhar.aseem.diva   // DIVA's root package

import android.app.Application
import android.util.Log
import com.aheaditec.talsec.security.Talsec
import com.aheaditec.talsec.security.TalsecConfig
import com.aheaditec.talsec.security.ThreatListener

class DivaApp : Application(), ThreatListener.ThreatDetected {

    override fun onCreate() {
        super.onCreate()

        val config = TalsecConfig.Builder(
            "jakhar.aseem.diva",                       // expectedPackageName
            byteArrayOf( /* expected signing cert SHA-256 */ )
        )
            .watcherMail("secops@example.com")
            .supportedAlternativeStores(listOf())      // empty → reject sideloads
            .prod(true)
            .build()

        ThreatListener(this).registerListener(this)
        Talsec.start(this, config)
    }

    override fun onRootDetected()        = react("root")
    override fun onDebuggerDetected()    = react("debugger")
    override fun onEmulatorDetected()    = react("emulator")
    override fun onTamperDetected()      = react("repackage/tamper")
    override fun onUntrustedInstallationSourceDetected() = react("sideload")
    override fun onHookDetected()        = react("frida/xposed")
    override fun onDeviceBindingDetected() = react("device-rebind")
    override fun onObfuscationIssuesDetected() = react("not-obfuscated")
    override fun onMalwareDetected(packageInfos: MutableList<com.aheaditec.talsec.security.SuspiciousAppInfo>?) =
        react("known-malware")

    private fun react(kind: String) {
        Log.w("freeRASP", "threat: $kind — killing session")
        // Production reaction: invalidate session, force re-auth, then exit.
        android.os.Process.killProcess(android.os.Process.myPid())
    }
}
