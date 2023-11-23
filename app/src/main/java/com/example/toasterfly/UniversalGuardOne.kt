package com.example.toasterfly

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

object UniversalGuardOne {
//    companion object {
    private val _isLibraryLoaded = MutableLiveData<Boolean>()
    val isLibraryLoaded: LiveData<Boolean> get() = _isLibraryLoaded

        init {
            GlobalScope.launch {
                loadLibrary()
            }
//            GlobalScope.launch {
//                try {
//                    loadLibrary()
////                    if (isLibraryLoaded) {
////                        executeMethod()
////                    }
//                } catch (e: Exception) {
//                    e.printStackTrace()
//                }
//            }
        }

        private fun loadLibrary() {
            try {
                System.loadLibrary("native-lib")
                _isLibraryLoaded.postValue(true)
            } catch (e: UnsatisfiedLinkError) {
                _isLibraryLoaded.postValue(false)
            }
        }


        fun startProtectingUniverse(context: Context?): Boolean {
            try {
//            System.loadLibrary("native-lib");
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
                return false
            }
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
                //                abortApp();
            }, 3000)
        }

        external fun haveSu(): Int

        external fun haveMagiskHide(): Int

        external fun haveMagicMount(): Int

        external fun detectFrida(): Boolean

        external fun abortApp()

//    }

}