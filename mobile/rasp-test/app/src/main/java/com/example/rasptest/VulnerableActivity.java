package com.example.rasptest;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebSettings;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

public class VulnerableActivity extends Activity {

    // Hardcoded AWS secret — triggers android-hardcoded-secret
    String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // WebView with JavaScript enabled — triggers android-webview-js-enabled
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().allowFileAccess(true);
        webView.loadUrl("http://example.com");

        // SQLite string concatenation — triggers android-sqlite-string-concat
        String userInput = "'; DROP TABLE users; --";
        SQLiteDatabase db = openOrCreateDatabase("test.db", MODE_PRIVATE, null);
        db.execSQL("SELECT * FROM users WHERE name = '" + userInput + "'");

        Log.i("RASPTest", "Vulnerable activity started");
    }
}
