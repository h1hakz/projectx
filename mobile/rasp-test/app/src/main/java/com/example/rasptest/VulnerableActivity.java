package com.example.rasptest;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebSettings;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

public class VulnerableActivity extends Activity {

    // Hardcoded AWS secret — triggers android-hardcoded-secret
    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // WebView with JavaScript enabled — triggers android-webview-js-enabled
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.allowFileAccess(true);
        webView.loadUrl("http://example.com");

        // SQLite string concatenation — triggers android-sqlite-string-concat
        String userInput = "'; DROP TABLE users; --";
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        SQLiteDatabase db = openOrCreateDatabase("test.db", MODE_PRIVATE, null);
        db.execSQL(query);

        Log.i("RASPTest", "Vulnerable activity started");
    }
}
