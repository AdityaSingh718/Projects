package com.example.eswproject

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel that manages pose detection using our hybrid backend system
 * Integrates with MainActivity and provides pose detection results
 */
class PoseDetectionViewModel : ViewModel() {
    
    private val TAG = "PoseDetectionViewModel"
    
    private var poseBackend: PoseDetectionBackend? = null
    private val firebaseService = RealtimeFirebaseService()
    private var currentSessionId: String? = null
    private var lastFirebaseUploadTime: Long = 0L
    
    // Current pose detection state
    private val _poseState = MutableStateFlow(PoseDetectionState())
    val poseState: StateFlow<PoseDetectionState> = _poseState.asStateFlow()
    
    // Backend information
    private val _backendInfo = MutableStateFlow(BackendInfo())
    val backendInfo: StateFlow<BackendInfo> = _backendInfo.asStateFlow()
    
    // Performance metrics for runtime monitoring
    private val _performanceMetrics = MutableStateFlow(PerformanceMetrics())
    val performanceMetrics: StateFlow<PerformanceMetrics> = _performanceMetrics.asStateFlow()
    
    // Current runtime provider
    private val _currentRuntime = MutableStateFlow(RuntimeProvider.CPU)
    val currentRuntime: StateFlow<RuntimeProvider> = _currentRuntime.asStateFlow()

    // Session tracking state
    private val _sessionStartTime = MutableStateFlow<Long?>(null)
    val sessionStartTime: StateFlow<Long?> = _sessionStartTime.asStateFlow()

    private val _sessionEndTime = MutableStateFlow<Long?>(null)
    val sessionEndTime: StateFlow<Long?> = _sessionEndTime.asStateFlow()

    private val _currentSessionDuration = MutableStateFlow(0L)
    val currentSessionDuration: StateFlow<Long> = _currentSessionDuration.asStateFlow()

    private val _activeSession = MutableStateFlow(false)
    val activeSession: StateFlow<Boolean> = _activeSession.asStateFlow()

    private var lastPersonDetected: Boolean = false

    // Posture history tracking
    private val _postureHistory = MutableStateFlow<List<PostureEntry>>(emptyList())
    val postureHistory: StateFlow<List<PostureEntry>> = _postureHistory.asStateFlow()
    private var lastHistoryRecordTime: Long = 0L

    init {
        // Ticker to update session duration every second while active
        viewModelScope.launch {
            while (true) {
                if (_activeSession.value && _sessionStartTime.value != null) {
                    _currentSessionDuration.value = System.currentTimeMillis() - _sessionStartTime.value!!
                }
                kotlinx.coroutines.delay(1000)
            }
        }
        
        // Update session statistics every 30 seconds while active
        viewModelScope.launch {
            while (true) {
                if (_activeSession.value && currentSessionId != null) {
                    updateLiveSessionStats()
                }
                kotlinx.coroutines.delay(30000) // 30 seconds
            }
        }
    }
    
    /**
     * Update session statistics while session is active
     */
    private fun updateLiveSessionStats() {
        currentSessionId?.let { sessionId ->
            viewModelScope.launch {
                val history = _postureHistory.value
                val currentTime = System.currentTimeMillis()
                
                // Filter valid scores from current session
                val sessionScores = history
                    .filter { entry -> 
                        entry.score > 0 && 
                        entry.timestamp >= (_sessionStartTime.value ?: 0L) && 
                        entry.timestamp <= currentTime 
                    }
                    .map { it.score }
                
                if (sessionScores.isNotEmpty()) {
                    val avgScore = sessionScores.average()
                    val maxScore = sessionScores.maxOrNull() ?: 0
                    val minScore = sessionScores.minOrNull() ?: 0
                    val duration = currentTime - (_sessionStartTime.value ?: currentTime)
                    
                    firebaseService.updateSessionData(
                        sessionId = sessionId,
                        duration = duration,
                        totalDataPoints = sessionScores.size,
                        averageScore = avgScore,
                        maxScore = maxScore,
                        minScore = minScore,
                        isActive = true
                    ).onSuccess { 
                        Log.d(TAG, "Live session stats updated: ${sessionScores.size} points, avg: $avgScore") 
                    }.onFailure { 
                        Log.w(TAG, "Failed to update live session stats", it) 
                    }
                }
            }
        }
    }
    
    /**
     * Initialize the pose detection backend and test Firebase connection
     */
    fun initializeBackend(context: Context) {
        // Test Firebase connection
        viewModelScope.launch {
            firebaseService.testConnection()
                .onSuccess { Log.i(TAG, "Firebase connection successful") }
                .onFailure { Log.w(TAG, "Firebase connection failed - data will not be uploaded", it) }
        }
        viewModelScope.launch {
            try {
                Log.d(TAG, "Initializing pose detection backend...")
                
                // Create appropriate backend based on hardware
                poseBackend = PoseDetectionBackendFactory.createBackend(context)
                
                // Initialize the backend
                val success = poseBackend?.initialize(context) ?: false
                
                if (success) {
                    // Update backend info
                    val recommendedBackend = HardwareDetector.getRecommendedBackend()
                    val performanceTier = HardwareDetector.getPerformanceTier()
                    val isQualcomm = HardwareDetector.isQualcommDevice()
                    
                    _backendInfo.value = BackendInfo(
                        isInitialized = true,
                        currentBackend = recommendedBackend,
                        performanceTier = performanceTier,
                        isQualcommDevice = isQualcomm,
                        error = null
                    )
                    
                    Log.i(TAG, "Backend initialized successfully: $recommendedBackend")
                } else {
                    _backendInfo.value = BackendInfo(
                        isInitialized = false,
                        error = "Failed to initialize pose detection backend"
                    )
                    Log.e(TAG, "Failed to initialize backend")
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error initializing backend", e)
                _backendInfo.value = BackendInfo(
                    isInitialized = false,
                    error = "Backend initialization error: ${e.message}"
                )
            }
        }
    }
    
    /**
     * Process a bitmap for pose detection
     */
    fun detectPose(bitmap: Bitmap) {
        viewModelScope.launch {
            try {
                val backend = poseBackend
                if (backend == null) {
                    Log.w(TAG, "Backend not initialized")
                    return@launch
                }
                
                _poseState.value = _poseState.value.copy(isProcessing = true)
                
                // Run pose detection
                val result = backend.detectAndPose(bitmap)
                
                // Update state with results
                _poseState.value = PoseDetectionState(
                    isProcessing = false,
                    persons = result.persons,
                    inferenceTime = result.inferenceTime,
                    lastUpdate = System.currentTimeMillis(),
                    error = null
                )
                
                Log.d(TAG, "Pose detection completed: ${result.persons.size} persons found in ${result.inferenceTime}ms")
                
            } catch (e: Exception) {
                Log.e(TAG, "Error during pose detection", e)
                _poseState.value = _poseState.value.copy(
                    isProcessing = false,
                    error = "Pose detection error: ${e.message}"
                )
            }
        }
    }

    // External direct update (ML Kit path) before full backend pipeline done
    fun detectFromExternal(persons: List<PersonDetection>) {
        _poseState.value = PoseDetectionState(
            isProcessing = false,
            persons = persons,
            inferenceTime = 0,
            lastUpdate = System.currentTimeMillis(),
            error = null
        )

        // Update session tracking based on presence of persons
        val detected = persons.isNotEmpty()
        if (detected && !lastPersonDetected) {
            // Start session
            val startTime = System.currentTimeMillis()
            _sessionStartTime.value = startTime
            _sessionEndTime.value = null
            _activeSession.value = true
            _currentSessionDuration.value = 0L
            
            // Create new session ID and upload to Firebase
            currentSessionId = firebaseService.generateSessionId()
            Log.d(TAG, "Starting new session: $currentSessionId")
            
            viewModelScope.launch {
                val sessionData = RealtimeFirebaseService.SessionData(
                    sessionId = currentSessionId!!,
                    startTime = startTime,
                    isActive = true
                )
                firebaseService.uploadSessionData(sessionData)
                    .onSuccess { Log.d(TAG, "Session start uploaded successfully: $currentSessionId") }
                    .onFailure { Log.w(TAG, "Failed to upload session start to Firebase", it) }
            }
        }
        if (!detected && lastPersonDetected) {
            // End session
            val endTime = System.currentTimeMillis()
            _sessionEndTime.value = endTime
            _activeSession.value = false
            
            // Update session in Firebase with final stats
            currentSessionId?.let { sessionId ->
                viewModelScope.launch {
                    val history = _postureHistory.value
                    val duration = endTime - (_sessionStartTime.value ?: endTime)
                    
                    // Filter valid scores from this session only
                    val sessionScores = history
                        .filter { entry -> 
                            entry.score > 0 && 
                            entry.timestamp >= (_sessionStartTime.value ?: 0L) && 
                            entry.timestamp <= endTime 
                        }
                        .map { it.score }
                    
                    Log.d(TAG, "Session ending - found ${sessionScores.size} valid data points")
                    
                    val avgScore = if (sessionScores.isNotEmpty()) sessionScores.average() else 0.0
                    val maxScore = if (sessionScores.isNotEmpty()) sessionScores.maxOrNull() ?: 0 else 0
                    val minScore = if (sessionScores.isNotEmpty()) sessionScores.minOrNull() ?: 0 else 0
                    
                    firebaseService.updateSessionData(
                        sessionId = sessionId,
                        endTime = endTime,
                        duration = duration,
                        totalDataPoints = sessionScores.size,
                        averageScore = avgScore,
                        maxScore = maxScore,
                        minScore = minScore,
                        isActive = false
                    ).onSuccess { 
                        Log.d(TAG, "Session updated: ${sessionScores.size} points, avg: $avgScore, max: $maxScore, min: $minScore") 
                    }.onFailure { 
                        Log.w(TAG, "Failed to update session end in Firebase", it) 
                    }
                }
            }
        }
        lastPersonDetected = detected
    }

    fun recordPostureIfNeeded(poseDescription: String, score: Int) {
        // Do not record if no person or score zero
        if (score <= 0 || poseDescription.lowercase().contains("no person")) return
        val now = System.currentTimeMillis()
        if (now - lastHistoryRecordTime < 1500) return // throttle local history to every 1.5s
        lastHistoryRecordTime = now
        
        viewModelScope.launch {
            val newEntry = PostureEntry(poseDescription, score, now)
            val updated = (_postureHistory.value + newEntry).let { list ->
                if (list.size > 300) list.drop(list.size - 300) else list
            }
            _postureHistory.value = updated
            
            Log.d(TAG, "Added posture entry: $poseDescription, score: $score, total entries: ${updated.size}")
            
            currentSessionId?.let { sessionId ->
                // Upload current status immediately (for real-time monitoring)
                firebaseService.uploadCurrentStatus(
                    score = score,
                    label = poseDescription,
                    sessionId = sessionId
                ).onFailure { 
                    Log.w(TAG, "Failed to upload current status to Firebase", it) 
                }
                
                // Upload detailed posture data every 10 seconds
                if (now - lastFirebaseUploadTime >= 10000) { // 10 seconds
                    lastFirebaseUploadTime = now
                    firebaseService.uploadPostureData(
                        score = score,
                        label = poseDescription,
                        sessionId = sessionId
                    ).onSuccess {
                        Log.d(TAG, "Uploaded detailed posture data: $poseDescription, score: $score")
                    }.onFailure { 
                        Log.w(TAG, "Failed to upload posture data to Firebase", it) 
                    }
                }
            }
        }
    }

    private val _overridePoseLabel = MutableStateFlow<String?>(null)
    fun overridePoseLabel(label: String) { _overridePoseLabel.value = label }
    fun currentOverrideLabel(): String? = _overridePoseLabel.value
    
    private val _overridePostureScore = MutableStateFlow<Int?>(null)
    fun overridePostureScore(score: Int) { _overridePostureScore.value = score }
    fun currentOverrideScore(): Int? = _overridePostureScore.value
    
    /**
     * Get a simple posture score based on detected poses
     */
    fun getPostureScore(): Int {
        val currentState = _poseState.value
        if (currentState.persons.isEmpty()) {
            return 0 // Return 0 when no person detected
        }
        
        // Use override score if available (from ML classifier)
        currentOverrideScore()?.let { return it }
        
        // Fallback to label-based scoring
        currentOverrideLabel()?.let { return PostureHeuristics.scoreFor(it) }
    val person = currentState.persons.first()
    return calculatePostureScore(person.keypoints)
    }
    
    /**
     * Get current pose description
     */
    fun getPoseDescription(): String {
        // If no persons and no explicit override, show friendly message
        if (_poseState.value.persons.isEmpty() && _overridePoseLabel.value == null) {
            return "No person detected"
        }
        currentOverrideLabel()?.let { label ->
            return when (label.lowercase()) {
                "straight" -> "Excellent Posture"
                "hunchback" -> "Hunched Forward"
                "neck_bent", "neck bent" -> "Neck Forward"
                "neck_down", "neck down" -> "Looking Down"
                "recline" -> "Leaning Back"
                else -> label.replaceFirstChar { it.uppercase() }
            }
        }
        val score = getPostureScore()
        return when {
            score >= 85 -> "Excellent Posture"
            score >= 70 -> "Good Posture"
            score >= 55 -> "Fair Posture"
            score >= 40 -> "Poor Posture"
            else -> "Adjust Posture" // avoids "Very Poor Posture" wording on UI
        }
    }
    
    /**
     * Calculate a simple posture score from keypoints
     */
    private fun calculatePostureScore(keypoints: List<Keypoint>): Int {
        // This is a simplified scoring algorithm
        // In a real implementation, you'd analyze shoulder alignment, head position, etc.
        
        val noseKeypoint = keypoints.find { it.type == KeypointType.NOSE }
        val leftShoulder = keypoints.find { it.type == KeypointType.LEFT_SHOULDER }
        val rightShoulder = keypoints.find { it.type == KeypointType.RIGHT_SHOULDER }
        
        if (noseKeypoint == null || leftShoulder == null || rightShoulder == null) {
            return 50 // Default if keypoints not found
        }
        
        // Check if shoulders are level (good posture indicator)
        val shoulderDifference = kotlin.math.abs(leftShoulder.y - rightShoulder.y)
        val shoulderScore = if (shoulderDifference < 20) 90 else 60
        
        // Check head position relative to shoulders
        val shoulderCenterY = (leftShoulder.y + rightShoulder.y) / 2
        val headAlignment = if (noseKeypoint.y < shoulderCenterY - 30) 90 else 70
        
        // Combine scores (simplified)
        return ((shoulderScore + headAlignment) / 2).toInt()
    }
    
    /**
     * Update performance metrics (called by pose detector)
     */
    fun updatePerformanceMetrics(metrics: PerformanceMetrics) {
        _performanceMetrics.value = metrics
        _currentRuntime.value = metrics.runtimeProvider
    }
    
    /**
     * Switch runtime provider for ONNX inference
     */
    fun switchRuntime(context: Context, newRuntime: RuntimeProvider) {
        viewModelScope.launch {
            try {
                val backend = poseBackend
                if (backend is YoloV11PoseDetector) {
                    val success = backend.switchRuntime(context, newRuntime)
                    if (success) {
                        _currentRuntime.value = newRuntime
                        Log.i(TAG, "Successfully switched to ${newRuntime.displayName}")
                    } else {
                        Log.e(TAG, "Failed to switch runtime to ${newRuntime.displayName}")
                    }
                } else {
                    Log.w(TAG, "Backend does not support runtime switching")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error switching runtime", e)
            }
        }
    }
    
    override fun onCleared() {
        super.onCleared()
        poseBackend?.release()
        Log.d(TAG, "ViewModel cleared, backend released")
    }
}

data class PostureEntry(
    val label: String,
    val score: Int,
    val timestamp: Long
)

/**
 * State representing current pose detection results
 */
data class PoseDetectionState(
    val isProcessing: Boolean = false,
    val persons: List<PersonDetection> = emptyList(),
    val inferenceTime: Long = 0,
    val lastUpdate: Long = 0,
    val error: String? = null
)

/**
 * Information about the current backend
 */
data class BackendInfo(
    val isInitialized: Boolean = false,
    val currentBackend: MLBackend = MLBackend.TENSORFLOW_LITE,
    val performanceTier: PerformanceTier = PerformanceTier.LOW,
    val isQualcommDevice: Boolean = false,
    val error: String? = null
)