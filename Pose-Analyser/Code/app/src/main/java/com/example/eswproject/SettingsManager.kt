package com.example.eswproject

import android.content.Context
import android.content.SharedPreferences

/**
 * Manages app settings including posture detection mode preferences
 */
object SettingsManager {
    private const val PREFS_NAME = "posture_detection_settings"
    private const val KEY_POSTURE_MODE = "posture_detection_mode"
    private const val KEY_USER_ID = "current_user_id"
    private const val KEY_PERSONALIZED_SETUP_COMPLETE = "personalized_setup_complete"
    private const val KEY_PERSONALIZED_USERS = "personalized_user_list"
    private const val KEY_PERSONALIZED_SETUP_PREFIX = "personalized_setup_complete_"
    private const val KEY_PROFILE_IMAGE_PREFIX = "profile_image_uri_"
    private const val KEY_CONFIDENCE_THRESHOLD = "confidence_threshold"
    
    // Default confidence threshold (0.75 = 75%)
    const val DEFAULT_CONFIDENCE_THRESHOLD = 0.75f
    const val MIN_CONFIDENCE_THRESHOLD = 0.0f
    const val MAX_CONFIDENCE_THRESHOLD = 1.0f
    
    enum class PostureDetectionMode {
        STANDARD,      // Rule-based PostureDetector
        PERSONALIZED   // LightGBM personalized model
    }
    
    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    
    /**
     * Get current posture detection mode
     */
    fun getPostureMode(context: Context): PostureDetectionMode {
        val prefs = getPrefs(context)
        val modeStr = prefs.getString(KEY_POSTURE_MODE, PostureDetectionMode.STANDARD.name)
        return try {
            PostureDetectionMode.valueOf(modeStr ?: PostureDetectionMode.STANDARD.name)
        } catch (e: Exception) {
            PostureDetectionMode.STANDARD
        }
    }
    
    /**
     * Set posture detection mode
     */
    fun setPostureMode(context: Context, mode: PostureDetectionMode) {
        getPrefs(context).edit()
            .putString(KEY_POSTURE_MODE, mode.name)
            .apply()
    }
    
    /**
     * Get current user ID for personalized mode
     */
    fun getUserId(context: Context): String {
        val prefs = getPrefs(context)
        val id = prefs.getString(KEY_USER_ID, "default_user") ?: "default_user"
        ensureUserRecorded(prefs, id)
        return id
    }
    
    /**
     * Set current user ID
     */
    fun setUserId(context: Context, userId: String) {
        if (userId.isBlank()) return
        val prefs = getPrefs(context)
        ensureUserRecorded(prefs, userId)
        prefs.edit()
            .putString(KEY_USER_ID, userId.trim())
            .apply()
    }

    fun getPersonalizedUsers(context: Context): List<String> {
        val prefs = getPrefs(context)
        val set = prefs.getStringSet(KEY_PERSONALIZED_USERS, null)?.toMutableSet()
            ?: mutableSetOf("default_user")
        val current = prefs.getString(KEY_USER_ID, "default_user") ?: "default_user"
        if (!set.contains(current)) {
            set.add(current)
            prefs.edit().putStringSet(KEY_PERSONALIZED_USERS, set).apply()
        }
        return set.map { it.trim() }.filter { it.isNotBlank() }.distinct().sorted()
    }

    fun addPersonalizedUser(context: Context, userId: String): List<String> {
        if (userId.isBlank()) return getPersonalizedUsers(context)
        val prefs = getPrefs(context)
        val set = prefs.getStringSet(KEY_PERSONALIZED_USERS, null)?.toMutableSet()
            ?: mutableSetOf()
        set.add(userId.trim())
        prefs.edit().putStringSet(KEY_PERSONALIZED_USERS, set).apply()
        return set.map { it.trim() }.filter { it.isNotBlank() }.distinct().sorted()
    }

    fun removePersonalizedUser(context: Context, userId: String) {
        val prefs = getPrefs(context)
        val set = prefs.getStringSet(KEY_PERSONALIZED_USERS, null)?.toMutableSet() ?: return
        if (set.remove(userId)) {
            prefs.edit().putStringSet(KEY_PERSONALIZED_USERS, set).apply()
        }
    }
    
    /**
     * Check if personalized mode setup is complete
     */
    fun isPersonalizedSetupComplete(context: Context, userId: String = getUserId(context)): Boolean {
        val prefs = getPrefs(context)
        val key = KEY_PERSONALIZED_SETUP_PREFIX + userId
        if (prefs.contains(key)) {
            return prefs.getBoolean(key, false)
        }

        // Legacy fallback to single global flag
        val legacy = prefs.getBoolean(KEY_PERSONALIZED_SETUP_COMPLETE, false)
        if (legacy) {
            prefs.edit()
                .putBoolean(key, true)
                .remove(KEY_PERSONALIZED_SETUP_COMPLETE)
                .apply()
        }
        return legacy
    }
    
    /**
     * Mark personalized mode setup as complete
     */
    fun setPersonalizedSetupComplete(
        context: Context,
        complete: Boolean,
        userId: String = getUserId(context)
    ) {
        getPrefs(context).edit()
            .putBoolean(KEY_PERSONALIZED_SETUP_COMPLETE, complete) // legacy value
            .putBoolean(KEY_PERSONALIZED_SETUP_PREFIX + userId, complete)
            .apply()
    }

    /**
     * Get profile image URI for a user
     */
    fun getProfileImageUri(context: Context, userId: String): String? {
        return getPrefs(context).getString(KEY_PROFILE_IMAGE_PREFIX + userId, null)
    }

    /**
     * Set profile image URI for a user
     */
    fun setProfileImageUri(context: Context, userId: String, imageUri: String?) {
        getPrefs(context).edit()
            .putString(KEY_PROFILE_IMAGE_PREFIX + userId, imageUri)
            .apply()
    }

    /**
     * Get keypoint confidence threshold for posture filtering
     */
    fun getConfidenceThreshold(context: Context): Float {
        return getPrefs(context).getFloat(KEY_CONFIDENCE_THRESHOLD, DEFAULT_CONFIDENCE_THRESHOLD)
            .coerceIn(MIN_CONFIDENCE_THRESHOLD, MAX_CONFIDENCE_THRESHOLD)
    }

    /**
     * Set keypoint confidence threshold for posture filtering
     */
    fun setConfidenceThreshold(context: Context, threshold: Float) {
        getPrefs(context).edit()
            .putFloat(KEY_CONFIDENCE_THRESHOLD, threshold.coerceIn(MIN_CONFIDENCE_THRESHOLD, MAX_CONFIDENCE_THRESHOLD))
            .apply()
    }

    private fun ensureUserRecorded(prefs: SharedPreferences, userId: String) {
        val trimmed = userId.trim().ifEmpty { return }
        val set = prefs.getStringSet(KEY_PERSONALIZED_USERS, null)?.toMutableSet()
            ?: mutableSetOf()
        if (!set.contains(trimmed)) {
            set.add(trimmed)
            prefs.edit().putStringSet(KEY_PERSONALIZED_USERS, set).apply()
        }
    }
}
