package com.example.rasptest;

import android.app.Application;
import android.util.Log;

public class RaspTestApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i("RASPTest", "App started without freeRASP integration");
    }
}
