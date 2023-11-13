package com.example.toastmylibrary;

import android.content.Context;
import android.widget.Toast;

public class UniverseGuard {

//    static {
//        try {
//            System.loadLibrary("native-lib");
//        }catch (Exception e){
//            e.printStackTrace();
//        }
//    }


    public boolean startProtectingUniverse(Context context) {
        try {
            System.loadLibrary("native-lib");
            if (detectFrida()) {
                Toast.makeText(context,"Frida Magisk Detect",Toast.LENGTH_LONG).show();
                abortApp();
                return true;
            } else if (setValue(haveSu())) {
                Toast.makeText(context,"Frida Magisk Detect",Toast.LENGTH_LONG).show();
                abortApp();
                return true;
            } else if (setValueMagicMount(haveMagicMount())) {
                Toast.makeText(context,"Frida Magisk Detect",Toast.LENGTH_LONG).show();
                abortApp();
                return true;
            } else if (setValueMagiskHide(haveMagiskHide())) {
                Toast.makeText(context,"Frida Magisk Detect",Toast.LENGTH_LONG).show();
                abortApp();
                return true;
            }
        } catch (Throwable e) {
            return false;
        }
        return false;
    }

    private boolean setValue(Integer haveSu) {
        if (haveSu == 1) {
            return true;
        }
        return false;
    }

    private boolean setValueMagicMount(Integer haveMagicMount) {
        if (haveMagicMount >= 1) {
            return true;
        }
        return false;
    }

    private boolean setValueMagiskHide(Integer magiskdHide) {
        if (magiskdHide >= 1) {
            return true;
        }
        return false;
    }


    public int getHaveSu() {
        return haveSu();
    }

    public int getHaveMagiskHide() {
        return haveMagiskHide();
    }

    public int getHaveMagicMount() {
        return haveMagicMount();
    }

    public boolean startFridaDetection(){
        return detectFrida();
    }

    native int haveSu();

    native int haveMagiskHide();

    native int haveMagicMount();

    native boolean detectFrida();

    native void abortApp();

}
