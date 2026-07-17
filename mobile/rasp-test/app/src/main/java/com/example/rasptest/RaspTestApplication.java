package com.example.rasptest;

import android.app.Application;
import android.util.Log;
import com.aheaditec.talsec.security.Talsec;
import com.aheaditec.talsec.security.TalsecConfig;
import com.aheaditec.talsec.security.ThreatListener;

public class RaspTestApplication extends Application implements ThreatListener.ThreatDetected {

    @Override
    public void onCreate() {
        super.onCreate();

        TalsecConfig config = new TalsecConfig.Builder(
                "com.example.rasptest",
                new byte[] { }
        )
                .watcherMail("secops@example.com")
                .supportedAlternativeStores(new java.util.ArrayList<>())
                .prod(true)
                .build();

        ThreatListener threatListener = new ThreatListener(this);
        threatListener.registerListener(this);
        // Talsec.start(this, config);  // INTENTIONALLY COMMENTED OUT TO TRIGGER RASP ISSUE
    }

    @Override
    public void onRootDetected() {
        react("root");
    }

    @Override
    public void onDebuggerDetected() {
        react("debugger");
    }

    @Override
    public void onEmulatorDetected() {
        react("emulator");
    }

    @Override
    public void onTamperDetected() {
        react("repackage/tamper");
    }

    @Override
    public void onUntrustedInstallationSourceDetected() {
        react("sideload");
    }

    @Override
    public void onHookDetected() {
        react("frida/xposed");
    }

    @Override
    public void onDeviceBindingDetected() {
        react("device-rebind");
    }

    @Override
    public void onObfuscationIssuesDetected() {
        react("not-obfuscated");
    }

    @Override
    public void onMalwareDetected(java.util.List<com.aheaditec.talsec.security.SuspiciousAppInfo> suspiciousAppInfos) {
        react("known-malware");
    }

    private void react(String kind) {
        Log.w("freeRASP", "threat: " + kind + " — killing session");
        android.os.Process.killProcess(android.os.Process.myPid());
    }
}
