package com.example.eswproject

import android.content.Context
import androidx.camera.core.CameraSelector
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import com.google.common.util.concurrent.ListenableFuture
import java.util.concurrent.ExecutionException

/**
 * Helper class to manage camera selection and external USB camera detection
 * Provides utilities to automatically select the best available camera
 */
object CameraHelper {
    
    /**
     * Check if external USB camera is available
     * @return true if an external camera is connected and available
     */
    fun hasExternalCamera(context: Context): Boolean {
        return try {
            val cameraProviderFuture: ListenableFuture<ProcessCameraProvider> =
                ProcessCameraProvider.getInstance(context)
            val cameraProvider = cameraProviderFuture.get()
            
            cameraProvider.availableCameraInfos.any { cameraInfo ->
                val cameraSelector = CameraSelector.Builder()
                    .requireLensFacing(CameraSelector.LENS_FACING_EXTERNAL)
                    .build()
                try {
                    cameraSelector.filter(listOf(cameraInfo)).isNotEmpty()
                } catch (e: Exception) {
                    false
                }
            }
        } catch (e: ExecutionException) {
            android.util.Log.e("CameraHelper", "Error checking for external camera", e)
            false
        } catch (e: InterruptedException) {
            android.util.Log.e("CameraHelper", "Interrupted while checking for external camera", e)
            false
        }
    }
    
    /**
     * Get the appropriate camera selector based on availability
     * Priority order: External > Back > Front
     * @return CameraSelector configured for the best available camera
     */
    fun getCameraSelector(context: Context): CameraSelector {
        return when {
            hasExternalCamera(context) -> {
                android.util.Log.d("CameraHelper", "Using external USB camera")
                CameraSelector.Builder()
                    .requireLensFacing(CameraSelector.LENS_FACING_EXTERNAL)
                    .build()
            }
            else -> {
                android.util.Log.d("CameraHelper", "Using device back camera")
                CameraSelector.DEFAULT_BACK_CAMERA
            }
        }
    }
    
    /**
     * Get information about all available cameras
     * @return List of camera descriptions (Front, Back, External)
     */
    fun getAvailableCameras(context: Context): List<String> {
        return try {
            val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
            val cameraProvider = cameraProviderFuture.get()
            
            cameraProvider.availableCameraInfos.mapNotNull { info ->
                when {
                    CameraSelector.DEFAULT_FRONT_CAMERA.filter(listOf(info)).isNotEmpty() -> 
                        "Front Camera"
                    CameraSelector.DEFAULT_BACK_CAMERA.filter(listOf(info)).isNotEmpty() -> 
                        "Back Camera"
                    else -> {
                        // Check if it's an external camera
                        try {
                            val externalSelector = CameraSelector.Builder()
                                .requireLensFacing(CameraSelector.LENS_FACING_EXTERNAL)
                                .build()
                            if (externalSelector.filter(listOf(info)).isNotEmpty()) {
                                "External USB Camera"
                            } else {
                                "Unknown Camera"
                            }
                        } catch (e: Exception) {
                            "Unknown Camera"
                        }
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("CameraHelper", "Error getting available cameras", e)
            emptyList()
        }
    }
    
    /**
     * Get total number of available cameras
     */
    fun getCameraCount(context: Context): Int {
        return try {
            val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
            val cameraProvider = cameraProviderFuture.get()
            cameraProvider.availableCameraInfos.size
        } catch (e: Exception) {
            android.util.Log.e("CameraHelper", "Error getting camera count", e)
            0
        }
    }
    
    /**
     * Log all available cameras for debugging
     */
    fun logAvailableCameras(context: Context) {
        val cameras = getAvailableCameras(context)
        android.util.Log.d("CameraHelper", "=== Available Cameras (${cameras.size}) ===")
        cameras.forEachIndexed { index, camera ->
            android.util.Log.d("CameraHelper", "  [$index] $camera")
        }
        android.util.Log.d("CameraHelper", "=============================")
    }
}
