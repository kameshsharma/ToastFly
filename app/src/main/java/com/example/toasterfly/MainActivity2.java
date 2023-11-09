package com.example.toasterfly;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.system.Os;
import android.util.Log;
import android.widget.TextView;

public class MainActivity2 extends AppCompatActivity {
//    static {
//        try {
//            System.loadLibrary("native-lib");
//        }catch (Exception e){
//            e.printStackTrace();
//        }
//    }
    TextView text1 ;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        UniversalGuardOne mMagiskDetector=new UniversalGuardOne();
        text1 = this.findViewById(R.id.textv1);
        Log.e("frida==>", String.valueOf(mMagiskDetector.startFridaDetection()));
        int appId = Os.getuid() % 100000;
        if (appId >= 10000) {
            text1.setText(mMagiskDetector.detectFrida()+"\n"+String.valueOf(mMagiskDetector.getHaveSu())+"\n "+ String.valueOf(mMagiskDetector.getHaveMagicMount())+"\n "+String.valueOf(mMagiskDetector.getHaveMagiskHide()));
            Log.e("magisk haveSu", String.valueOf(mMagiskDetector.getHaveSu()));
            Log.e("magisk haveMagicMount", String.valueOf(mMagiskDetector.getHaveMagicMount()));
            Log.e("magisk haveMagiskHide", String.valueOf(mMagiskDetector.getHaveMagiskHide()));
        }
    }
}