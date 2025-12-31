package com.example.eswproject

import android.util.Log
import com.google.firebase.database.DatabaseReference
import com.google.firebase.database.FirebaseDatabase
import com.google.firebase.database.ktx.database
import com.google.firebase.ktx.Firebase
import kotlinx.coroutines.tasks.await
import java.text.SimpleDateFormat
import java.util.*

/**
 * Firebase Realtime Database service to handle posture data uploads
 */
class RealtimeFirebaseService {
    
    private val database: FirebaseDatabase = Firebase.database
    private val TAG = "RealtimeFirebaseService"
    
    /**
     * Data class representing posture data to be sent to Firebase Realtime Database
     */
    data class PostureData(
        val timestamp: Long = System.currentTimeMillis(),
        val formattedTime: String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date()),
        val postureScore: Int = 0,
        val postureLabel: String = "",
        val sessionId: String = "",
        val deviceInfo: String = "",
        val appVersion: String = "1.0"
    )
    
    /**
     * Data class for session information
     */
    data class SessionData(
        val sessionId: String = "",
        val startTime: Long = 0,
        val endTime: Long? = null,
        val duration: Long = 0,
        val totalDataPoints: Int = 0,
        val averageScore: Double = 0.0,
        val maxScore: Int = 0,
        val minScore: Int = 0,
        val isActive: Boolean = true,
        val lastUpdated: Long = System.currentTimeMillis()
    )
    
    /**
     * Upload posture data to Firebase Realtime Database
     */
    suspend fun uploadPostureData(
        score: Int,
        label: String,
        sessionId: String = generateSessionId()
    ): Result<String> {
        return try {
            val postureData = PostureData(
                postureScore = score,
                postureLabel = label,
                sessionId = sessionId,
                deviceInfo = android.os.Build.MODEL + " " + android.os.Build.VERSION.RELEASE
            )
            
            // Generate unique key for this data point
            val key = database.getReference("posture_data").push().key ?: return Result.failure(Exception("Failed to generate key"))
            
            // Upload to "posture_data" node
            database.getReference("posture_data").child(key).setValue(postureData).await()
            
            Log.d(TAG, "Posture data uploaded successfully with key: $key")
            Result.success(key)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error uploading posture data", e)
            Result.failure(e)
        }
    }
    
    /**
     * Upload session data to Firebase Realtime Database
     */
    suspend fun uploadSessionData(sessionData: SessionData): Result<String> {
        return try {
            // Upload to "sessions" node using sessionId as key
            database.getReference("sessions").child(sessionData.sessionId).setValue(sessionData).await()
            
            Log.d(TAG, "Session data uploaded successfully for session: ${sessionData.sessionId}")
            Result.success(sessionData.sessionId)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error uploading session data", e)
            Result.failure(e)
        }
    }
    
    /**
     * Update existing session data
     */
    suspend fun updateSessionData(
        sessionId: String,
        endTime: Long? = null,
        duration: Long = 0,
        totalDataPoints: Int = 0,
        averageScore: Double = 0.0,
        maxScore: Int = 0,
        minScore: Int = 0,
        isActive: Boolean = true
    ): Result<Unit> {
        return try {
            val updates = mutableMapOf<String, Any>()
            
            endTime?.let { updates["endTime"] = it }
            if (duration > 0) updates["duration"] = duration
            if (totalDataPoints > 0) updates["totalDataPoints"] = totalDataPoints
            if (averageScore > 0) updates["averageScore"] = averageScore
            if (maxScore > 0) updates["maxScore"] = maxScore
            if (minScore > 0) updates["minScore"] = minScore
            updates["isActive"] = isActive
            updates["lastUpdated"] = System.currentTimeMillis()
            
            database.getReference("sessions").child(sessionId).updateChildren(updates).await()
            
            Log.d(TAG, "Session updated successfully: $sessionId")
            Result.success(Unit)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error updating session data", e)
            Result.failure(e)
        }
    }
    
    /**
     * Generate a unique session ID based on timestamp
     */
    fun generateSessionId(): String {
        val timestamp = System.currentTimeMillis()
        val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        return "session_${dateFormat.format(Date(timestamp))}_${timestamp % 10000}"
    }
    
    /**
     * Batch upload multiple posture data points (for efficiency)
     */
    suspend fun batchUploadPostureData(
        postureDataList: List<PostureEntry>,
        sessionId: String
    ): Result<Int> {
        return try {
            val updates = mutableMapOf<String, Any>()
            var successCount = 0
            
            postureDataList.forEach { entry ->
                val postureData = PostureData(
                    timestamp = entry.timestamp,
                    postureScore = entry.score,
                    postureLabel = entry.label,
                    sessionId = sessionId,
                    deviceInfo = android.os.Build.MODEL + " " + android.os.Build.VERSION.RELEASE
                )
                
                val key = database.getReference("posture_data").push().key
                key?.let {
                    updates["posture_data/$it"] = postureData
                    successCount++
                }
            }
            
            database.reference.updateChildren(updates).await()
            Log.d(TAG, "Batch upload successful: $successCount items")
            Result.success(successCount)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in batch upload", e)
            Result.failure(e)
        }
    }
    
    /**
     * Test Firebase Realtime Database connection
     */
    suspend fun testConnection(): Result<Boolean> {
        return try {
            // Try to write a test value
            database.getReference("test").child("connection").setValue("test").await()
            Log.d(TAG, "Firebase Realtime Database connection test successful")
            Result.success(true)
        } catch (e: Exception) {
            Log.e(TAG, "Firebase Realtime Database connection test failed", e)
            Result.failure(e)
        }
    }
    
    /**
     * Upload current posture status (for real-time monitoring)
     */
    suspend fun uploadCurrentStatus(
        score: Int,
        label: String,
        sessionId: String
    ): Result<Unit> {
        return try {
            val statusData = mapOf(
                "currentScore" to score,
                "currentPosture" to label,
                "sessionId" to sessionId,
                "timestamp" to System.currentTimeMillis(),
                "formattedTime" to SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date()),
                "deviceInfo" to "${android.os.Build.MODEL} ${android.os.Build.VERSION.RELEASE}"
            )
            
            // Upload to "current_status" node - this will overwrite each time for live status
            database.getReference("current_status").setValue(statusData).await()
            
            Log.d(TAG, "Current status uploaded successfully")
            Result.success(Unit)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error uploading current status", e)
            Result.failure(e)
        }
    }
}