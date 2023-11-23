package com.example.toasterfly;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.system.Os;
import android.util.Log;
import android.widget.TextView;
import androidx.lifecycle.Observer;

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
//        UniversalGuardOne mMagiskDetector=new UniversalGuardOne;
        text1 = this.findViewById(R.id.textv1);
//        Log.e("frida==>", String.valueOf(mMagiskDetector.startProtectingUniverse()));
        int appId = Os.getuid() % 100000;
        if (appId >= 10000) {
            UniversalGuardOne.INSTANCE.isLibraryLoaded().observe(this, new Observer<Boolean>() {
                @Override
                public void onChanged(Boolean isLoaded) {
                    if (isLoaded != null && isLoaded) {
                        UniversalGuardOne.INSTANCE.startProtectingUniverse(MainActivity2.this);
                        text1.setText(UniversalGuardOne.INSTANCE.detectFrida()+"\n"+String.valueOf(UniversalGuardOne.INSTANCE.getHaveSu())+"\n "+ String.valueOf(UniversalGuardOne.INSTANCE.getHaveMagicMount())+"\n "+String.valueOf(UniversalGuardOne.INSTANCE.getHaveMagiskHide()));

                        // The library is loaded, you can update UI or perform other actions
                    } else {
                        // Handle the case where the library failed to load
                    }
                }
            });
//            if (UniversalGuardOne.Companion.isLibraryLoaded()) {
//                UniversalGuardOne.Companion.startProtectingUniverse(MainActivity2.this);
//                text1.setText(UniversalGuardOne.Companion.detectFrida()+"\n"+String.valueOf(UniversalGuardOne.Companion.getHaveSu())+"\n "+ String.valueOf(UniversalGuardOne.Companion.getHaveMagicMount())+"\n "+String.valueOf(UniversalGuardOne.Companion.getHaveMagiskHide()));
//            }
//            Log.e("frida==>", String.valueOf(mMagiskDetector.startProtectingUniverse(MainActivity2.this)));
//            text1.setText(mMagiskDetector.detectFrida()+"\n"+String.valueOf(mMagiskDetector.getHaveSu())+"\n "+ String.valueOf(mMagiskDetector.getHaveMagicMount())+"\n "+String.valueOf(mMagiskDetector.getHaveMagiskHide()));
//            Log.e("magisk haveSu", String.valueOf(mMagiskDetector.getHaveSu()));
//            Log.e("magisk haveMagicMount", String.valueOf(mMagiskDetector.getHaveMagicMount()));
//            Log.e("magisk haveMagiskHide", String.valueOf(mMagiskDetector.getHaveMagiskHide()));
        }

//        UniversalGuardOne mMagiskDetector=new UniversalGuardOne();
//        text1 = this.findViewById(R.id.textv1);
//        mMagiskDetector.startProtectingUniverse(MainActivity2.this);
////        Log.e("frida==>", String.valueOf(mMagiskDetector.startFridaDetection()));
//        int appId = Os.getuid() % 100000;
//
//        if (appId >= 10000) {
//            text1.setText(mMagiskDetector.detectFrida()+"\n"+String.valueOf(mMagiskDetector.getHaveSu())+"\n "+ String.valueOf(mMagiskDetector.getHaveMagicMount())+"\n "+String.valueOf(mMagiskDetector.getHaveMagiskHide()));
//            Log.e("magisk haveSu", String.valueOf(mMagiskDetector.getHaveSu()));
//            Log.e("magisk haveMagicMount", String.valueOf(mMagiskDetector.getHaveMagicMount()));
//            Log.e("magisk haveMagiskHide", String.valueOf(mMagiskDetector.getHaveMagiskHide()));
//        }
    }
}