package com.example.toastmylibrary

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class UniverseGuard {
    private val _isLibraryLoaded = MutableLiveData<Boolean>()
    val isLibraryLoaded: LiveData<Boolean> get() = _isLibraryLoaded
     private var isLibraryLoadedOne = false
     fun loadLibraryAndExecuteMethod(context: Context?) {
         GlobalScope.launch(Dispatchers.IO) {
             // Load the library in the background
             val libraryLoaded = loadLibrary()

             // Check if the library is loaded
             if (libraryLoaded) {
                 // Execute your method
                 withContext(Dispatchers.Main) {
                     startProtectingUniverse(context)
                 }
             }
         }
     }
//    private fun loadLibrary() {
//        try {
//            System.loadLibrary("native-lib")
//            isLibraryLoadedOne = true
//            _isLibraryLoaded.postValue(true)
//        } catch (e: UnsatisfiedLinkError) {
//            _isLibraryLoaded.postValue(false)
//        }
//    }
     suspend fun loadLibrary(): Boolean {
         return try {
             System.loadLibrary("native-lib")
             true
         } catch (e: UnsatisfiedLinkError) {
             e.printStackTrace()
             false
         }
     }
    fun startProtectingUniverse(context: Context?): Boolean {
        try {
            if (detectFrida()) {
                Toast.makeText(context, "Frida Magisk Detect", Toast.LENGTH_LONG).show()
                killMonster()
                //                abortApp();
                return true
            } else if (setValue(haveSu())) {
                Toast.makeText(context, "Frida Magisk Detect", Toast.LENGTH_LONG).show()
                killMonster()
                return true
            } else if (setValueMagicMount(haveMagicMount())) {
                Toast.makeText(context, "Frida Magisk Detect", Toast.LENGTH_LONG).show()
                killMonster()
                return true
            } else if (setValueMagiskHide(haveMagiskHide())) {
                Toast.makeText(context, "Frida Magisk Detect", Toast.LENGTH_LONG).show()
                killMonster()
                return true
            }
        } catch (e: Throwable) {
            Toast.makeText(context, "Frida Magisk Not Detect", Toast.LENGTH_LONG).show()
            return false
        }
        Toast.makeText(context, "Frida Magisk Not Detect", Toast.LENGTH_LONG).show()
        return false
    }

    fun getHaveSu(): Int {
        return haveSu()
    }

    fun getHaveMagiskHide(): Int {
        return haveMagiskHide()
    }

    fun getHaveMagicMount(): Int {
        return haveMagicMount()
    }

    fun startFridaDetection(): Boolean {
        return detectFrida()
    }

    private fun setValue(haveSu: Int): Boolean {
        return if (haveSu == 1) {
            true
        } else false
    }

    private fun setValueMagicMount(haveMagicMount: Int): Boolean {
        return if (haveMagicMount >= 1) {
            true
        } else false
    }

    private fun setValueMagiskHide(magiskdHide: Int): Boolean {
        return if (magiskdHide >= 1) {
            true
        } else false
    }

    private fun killMonster() {
        Handler(Looper.getMainLooper()).postDelayed({
            abortApp();
        }, 3000)
    }

    external fun haveSu(): Int

    external fun haveMagiskHide(): Int

    external fun haveMagicMount(): Int

    external fun detectFrida(): Boolean

    external fun abortApp()
}