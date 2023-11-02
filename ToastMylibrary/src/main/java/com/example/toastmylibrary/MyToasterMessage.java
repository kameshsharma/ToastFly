package com.example.toastmylibrary;

import android.content.Context;
import android.widget.Toast;

public class MyToasterMessage {
    public static void s(Context c, String message){

        Toast.makeText(c,message, Toast.LENGTH_SHORT).show();

    }
}
