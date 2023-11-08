package com.example.toasterfly;

public class FridaDetect {

    static {
        try {
            System.loadLibrary("native-lib");
        }catch (Exception e){
            e.printStackTrace();
        }
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
