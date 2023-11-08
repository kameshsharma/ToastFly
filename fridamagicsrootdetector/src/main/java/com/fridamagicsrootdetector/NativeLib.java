package com.fridamagicsrootdetector;

public class NativeLib {

    // Used to load the 'fridamagicsrootdetector' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

}