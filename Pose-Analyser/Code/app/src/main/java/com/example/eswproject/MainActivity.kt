package com.example.eswproject

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Paint
import android.graphics.PointF
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.view.LifecycleCameraController
import androidx.core.content.ContextCompat
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandHorizontally
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkHorizontally
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Accessibility
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DirectionsWalk
import androidx.compose.material.icons.filled.Face
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowLeft
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.graphics.asImageBitmap
import android.graphics.Bitmap
import com.example.eswproject.ui.theme.ESWProjectTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import java.text.SimpleDateFormat
import java.util.*

// Camera source modes
enum class CameraSource {
    USB_CAMERA,      // Physical USB or built-in camera
    NETWORK_STREAM   // Network MJPEG stream
}

sealed class Screen(val route: String, val title: String)
object HomeScreenRoute : Screen("home", "Home")
object CameraScreenRoute : Screen("camera", "Camera")
object HistoryScreenRoute : Screen("history", "History")
object SettingsScreenRoute : Screen("settings", "Settings")
object PersonalizedSetupScreenRoute : Screen("personalized_setup", "Personalized Setup")
object ProfileSelectionScreenRoute : Screen("profile_selection", "Choose Profile")

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ESWProjectTheme {
                val context = LocalContext.current
                val scope = rememberCoroutineScope()
                var hasPermissions by remember {
                    mutableStateOf(
                        CAMERAX_PERMISSIONS.all {
                            ContextCompat.checkSelfPermission(
                                context,
                                it
                            ) == PackageManager.PERMISSION_GRANTED
                        }
                    )
                }
                val launcher = rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestMultiplePermissions()
                ) { permissions ->
                    hasPermissions = permissions.values.all { it }
                }

                LaunchedEffect(Unit) {
                    if (!hasPermissions) {
                        launcher.launch(CAMERAX_PERMISSIONS)
                    }
                }

                // Defer camera controller creation until permissions granted to avoid crashes
                val cameraController: LifecycleCameraController? = remember(hasPermissions) {
                    if (hasPermissions) {
                        try {
                            LifecycleCameraController(context).apply { 
                                bindToLifecycle(this@MainActivity)
                                
                                // Use CameraHelper to automatically select best camera (external USB > back > front)
                                cameraSelector = CameraHelper.getCameraSelector(context)
                            }
                        } catch (e: Exception) {
                            e.printStackTrace()
                            null
                        }
                    } else null
                }
                
                // Log available cameras for debugging
                LaunchedEffect(hasPermissions) {
                    if (hasPermissions) {
                        CameraHelper.logAvailableCameras(context)
                    }
                }

                // Pose VM & backend init
                val poseViewModel = remember { PoseDetectionViewModel() }
                LaunchedEffect(Unit) { poseViewModel.initializeBackend(context) }

                // Posture detection mode and managers
                var postureMode by remember { mutableStateOf(SettingsManager.getPostureMode(context)) }
                var confidenceThreshold by remember { mutableStateOf(SettingsManager.getConfidenceThreshold(context)) }
                
                // Standalone Posture Detector (no network required) - Standard mode
                // Recreate when confidence threshold changes
                val postureDetector = remember(confidenceThreshold) { PostureDetector(confidenceThreshold) }
                
                // Personalized Posture Manager - Personalized mode
                val personalizedManager = remember { PersonalizedPostureManager(context) }
                var isPersonalizedInitialized by remember { mutableStateOf(false) }
                var isPersonalizedModelLoaded by remember { mutableStateOf(false) }
                var isInitializingPersonalized by remember { mutableStateOf(false) }
                var personalizedInitError by remember { mutableStateOf<String?>(null) }
                
                suspend fun ensurePersonalizedReady(): Boolean {
                    if (isPersonalizedInitialized) {
                        personalizedInitError = null
                        return true
                    }
                    if (isInitializingPersonalized) {
                        while (isInitializingPersonalized) {
                            delay(50)
                        }
                        return isPersonalizedInitialized
                    }

                    isInitializingPersonalized = true
                    personalizedInitError = null

                    val initSuccess = personalizedManager.initialize()
                    isPersonalizedInitialized = initSuccess

                    if (initSuccess) {
                        val userId = SettingsManager.getUserId(context)
                        isPersonalizedModelLoaded = personalizedManager.loadModel(userId)
                        if (!isPersonalizedModelLoaded) {
                            Log.d("MainActivity", "Personalized model not yet available for user")
                        }
                        personalizedInitError = null
                    } else {
                        personalizedInitError = personalizedManager.getLastErrorMessage()
                            ?: "Unable to initialize personalized mode. Please try again."
                    }

                    isInitializingPersonalized = false
                    return initSuccess
                }

                // Initialize personalized manager when in personalized mode
                LaunchedEffect(postureMode) {
                    if (postureMode == SettingsManager.PostureDetectionMode.PERSONALIZED) {
                        ensurePersonalizedReady()
                    }
                }

                val smoother = remember { PostureSmoother(window = 6) } // Moderate window smooths score jitter while staying responsive
                val landmarkSmoother = remember { PoseLandmarkSmoother(alpha = 0.45f) } // Heavier smoothing to stabilize keypoints across varying frame sizes

                var cameraSource by remember { mutableStateOf(CameraSource.USB_CAMERA) }
                
                // State for performance metrics and runtime switching
                val performanceMetrics by poseViewModel.performanceMetrics.collectAsState()
                val currentRuntime by poseViewModel.currentRuntime.collectAsState()
                var showRuntimeDialog by remember { mutableStateOf(false) }
                var yoloPoseAnalyzer by remember { mutableStateOf<YoloPoseAnalyzer?>(null) }
                var isSwitchingRuntime by remember { mutableStateOf(false) }

                // Attach YOLOv11 pose analyzer through controller
                LaunchedEffect(cameraController, hasPermissions, postureMode, cameraSource) {
                    if (!hasPermissions || cameraController == null) return@LaunchedEffect

                    runCatching { cameraController.clearImageAnalysisAnalyzer() }

                    if (cameraSource != CameraSource.USB_CAMERA) {
                        landmarkSmoother.reset()
                        yoloPoseAnalyzer = null
                        return@LaunchedEffect
                    }

                    runCatching {
                        val analyzer = YoloPoseAnalyzer(
                            context = context,
                            onPersonsDetected = { persons ->
                                val smoothedPersons = if (persons.isNotEmpty()) {
                                    landmarkSmoother.smooth(persons)
                                } else {
                                    landmarkSmoother.reset()
                                    emptyList()
                                }

                                poseViewModel.detectFromExternal(smoothedPersons)
                                if (smoothedPersons.isNotEmpty()) {
                                    // Choose detection mode based on settings
                                    if (postureMode == SettingsManager.PostureDetectionMode.PERSONALIZED && 
                                        isPersonalizedModelLoaded) {
                                        // Use Personalized LightGBM Model
                                        val result = postureDetector.analyzePosture(smoothedPersons)
                                        
                                        // Get angles for personalized prediction
                                        result.angles?.let { angles ->
                                            CoroutineScope(Dispatchers.Main).launch {
                                                val personalizedResult = personalizedManager.predict(
                                                    angles.neckAngle,
                                                    angles.backAngle,
                                                    angles.legsAngle
                                                )
                                                
                                                if (personalizedResult != null) {
                                                    smoother.reset()
                                                    poseViewModel.overridePoseLabel(personalizedResult.manualLabel)
                                                    poseViewModel.overridePostureScore(personalizedResult.score)
                                                    
                                                    android.util.Log.d("PosturePersonalized",
                                                        "ML: ${personalizedResult.mlPrediction} | " +
                                                        "Manual: ${personalizedResult.manualLabel} | " +
                                                        "Score: ${personalizedResult.score}/100")
                                                    if (personalizedResult.suggestions.isNotEmpty()) {
                                                        android.util.Log.d("PosturePersonalized", 
                                                            "Suggestions: ${personalizedResult.suggestions.joinToString(", ")}")
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        // Use Standard PostureDetector
                                        val result = postureDetector.analyzePosture(smoothedPersons)
                                        
                                        when (result.posture) {
                                            "NO_PERSON", "INCOMPLETE", "LOW_CONFIDENCE" -> {
                                                // Cannot analyze posture
                                                smoother.reset()
                                                poseViewModel.overridePoseLabel(result.message)
                                                poseViewModel.overridePostureScore(0)
                                                
                                                // Log reason for rejection
                                                if (result.posture == "LOW_CONFIDENCE" && result.suggestions.isNotEmpty()) {
                                                    android.util.Log.d("Posture", "Posture analysis skipped: ${result.message}")
                                                    android.util.Log.d("Posture", "Suggestions: ${result.suggestions.joinToString(", ")}")
                                                }
                                            }
                                            else -> {
                                                // Valid posture classification
                                                val postureLabel = result.posture
                                                val confidence = result.confidence
                                                
                                                smoother.add(postureLabel, confidence)
                                                val stable = smoother.current() ?: postureLabel
                                                // Use result.message for display (proper title case)
                                                poseViewModel.overridePoseLabel(result.message)
                                                // Use actual posture score from PostureDetector (0-100)
                                                poseViewModel.overridePostureScore(result.score)
                                                
                                                // Log angles and suggestions for debugging
                                                result.angles?.let { angles ->
                                                    android.util.Log.d("Posture", 
                                                        "Detected: $postureLabel (Score: ${result.score}/100) | " +
                                                        "Angles: legs=${"%.1f".format(angles.legsAngle)}° " +
                                                        "back=${"%.1f".format(angles.backAngle)}° " +
                                                        "neck=${"%.1f".format(angles.neckAngle)}°")
                                                }
                                                if (result.suggestions.isNotEmpty()) {
                                                    android.util.Log.d("Posture", "Suggestions: ${result.suggestions.joinToString(", ")}")
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    landmarkSmoother.reset()
                                    // No person detected - show appropriate message
                                    smoother.reset()
                                    poseViewModel.overridePoseLabel("No person detected to analyze posture")
                                    poseViewModel.overridePostureScore(0) // Reset score when no person
                                }
                            },
                            onPerformanceUpdate = { metrics ->
                                poseViewModel.updatePerformanceMetrics(metrics)
                            }
                        )
                        yoloPoseAnalyzer = analyzer
                        cameraController.setImageAnalysisAnalyzer(
                            ContextCompat.getMainExecutor(context),
                            analyzer
                        )
                    }.onFailure { it.printStackTrace() }
                }
                
                // Collect posture history from ViewModel
                val postureHistory by poseViewModel.postureHistory.collectAsState()

                // Collect session state from ViewModel
                val sessionStartTime by poseViewModel.sessionStartTime.collectAsState()
                val sessionEndTime by poseViewModel.sessionEndTime.collectAsState()
                val currentSessionDuration by poseViewModel.currentSessionDuration.collectAsState()
                val activeSession by poseViewModel.activeSession.collectAsState()

                // Get current pose state values
                val currentScore by remember { derivedStateOf { poseViewModel.getPostureScore() } }
                val currentPose by remember { derivedStateOf { poseViewModel.getPoseDescription() } }
                val currentSuggestion by remember { derivedStateOf { getPostureSuggestion(currentPose) } }

                // Record posture snapshots every 2 seconds while session active
                LaunchedEffect(activeSession) {
                    if (activeSession) {
                        while (true) {
                            val latestScore = poseViewModel.getPostureScore()
                            val latestPose = poseViewModel.getPoseDescription()
                            poseViewModel.recordPostureIfNeeded(latestPose, latestScore)
                            delay(2000)
                        }
                    }
                }

                // Removed demo seeding; history starts empty and fills with real data

                var currentScreen by remember { mutableStateOf<Screen>(HomeScreenRoute) }

                // Ensure the personalized manager is initialized when entering the setup flow
                LaunchedEffect(currentScreen) {
                    if (currentScreen == PersonalizedSetupScreenRoute) {
                        ensurePersonalizedReady()
                    }
                }

                // Reload model when user changes in personalized mode
                LaunchedEffect(postureMode) {
                    if (postureMode == SettingsManager.PostureDetectionMode.PERSONALIZED) {
                        val userId = SettingsManager.getUserId(context)
                        isPersonalizedModelLoaded = personalizedManager.loadModel(userId)
                    }
                }

                // Network streaming state
                var networkStreamUrl by remember { mutableStateOf("http://192.168.1.100:5000/video_feed") }
                var showNetworkSettings by remember { mutableStateOf(false) }
                var networkStreamBitmap by remember { mutableStateOf<Bitmap?>(null) }
                var networkStreamReceiver by remember { mutableStateOf<NetworkVideoStreamReceiver?>(null) }
                var networkStreamError by remember { mutableStateOf<String?>(null) }
                val networkYoloDetector = remember { YoloV11PoseDetector() }
                var networkDetectorReady by remember { mutableStateOf(false) }
                val networkFrameChannel = remember { Channel<Bitmap>(capacity = Channel.CONFLATED) }

                // Initialize network YOLO detector once
                LaunchedEffect(Unit) {
                    networkDetectorReady = networkYoloDetector.initialize(context)
                }
                
                // Handle network stream lifecycle
                LaunchedEffect(cameraSource, networkStreamUrl) {
                    if (cameraSource == CameraSource.NETWORK_STREAM) {
                        // Stop previous receiver if any
                        networkStreamReceiver?.stop()
                        networkStreamError = null
                        
                        // Create and start new receiver
                        networkStreamReceiver = NetworkVideoStreamReceiver(
                            streamUrl = networkStreamUrl,
                            onFrameReceived = { bitmap ->
                                networkStreamBitmap = bitmap
                                networkFrameChannel.trySend(bitmap)
                            },
                            onError = { error ->
                                networkStreamError = error
                                android.util.Log.e("NetworkStream", error)
                            }
                        ).apply {
                            start()
                        }
                    } else {
                        // Stop network stream when switching to USB camera
                        networkStreamReceiver?.stop()
                        networkStreamReceiver = null
                        networkStreamBitmap = null
                        networkStreamError = null
                    }
                }

                // Process network stream bitmaps through YOLO detector
                LaunchedEffect(cameraSource, networkDetectorReady) {
                    if (cameraSource != CameraSource.NETWORK_STREAM || !networkDetectorReady) {
                        return@LaunchedEffect
                    }

                    for (bitmap in networkFrameChannel) {
                        if (cameraSource != CameraSource.NETWORK_STREAM) {
                            break
                        }

                        val result = networkYoloDetector.detectAndPose(bitmap)
                        val persons = result.persons

                        val smoothedPersons = if (persons.isNotEmpty()) {
                            landmarkSmoother.smooth(persons)
                        } else {
                            landmarkSmoother.reset()
                            emptyList()
                        }

                        poseViewModel.detectFromExternal(smoothedPersons)
                        if (smoothedPersons.isNotEmpty()) {
                            val postureResult = postureDetector.analyzePosture(smoothedPersons)

                            when (postureResult.posture) {
                                "NO_PERSON", "INCOMPLETE" -> {
                                    smoother.reset()
                                    poseViewModel.overridePoseLabel(postureResult.message)
                                    poseViewModel.overridePostureScore(0)
                                }
                                else -> {
                                    val postureLabel = postureResult.posture
                                    val confidence = postureResult.confidence

                                    smoother.add(postureLabel, confidence)
                                    poseViewModel.overridePoseLabel(postureResult.message)
                                    poseViewModel.overridePostureScore(postureResult.score)

                                    postureResult.angles?.let { angles ->
                                        android.util.Log.d(
                                            "Posture",
                                            "Detected: $postureLabel (Score: ${postureResult.score}/100) | " +
                                                "Angles: legs=${"%.1f".format(angles.legsAngle)}° " +
                                                "back=${"%.1f".format(angles.backAngle)}° " +
                                                "neck=${"%.1f".format(angles.neckAngle)}°"
                                        )
                                    }
                                    if (postureResult.suggestions.isNotEmpty()) {
                                        android.util.Log.d("Posture", "Suggestions: ${postureResult.suggestions.joinToString(", ")}")
                                    }
                                }
                            }
                        } else {
                            landmarkSmoother.reset()
                            smoother.reset()
                            poseViewModel.overridePoseLabel("No person detected to analyze posture")
                            poseViewModel.overridePostureScore(0)
                        }
                    }
                }
                
                // Clean up network stream on dispose
                DisposableEffect(Unit) {
                    onDispose {
                        networkStreamReceiver?.stop()
                        networkYoloDetector.release()
                    }
                }

                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NavigationBarItem(
                                icon = { Icon(Icons.Filled.Home, contentDescription = "Home") },
                                label = { Text("Home") },
                                selected = currentScreen.route == HomeScreenRoute.route,
                                onClick = { currentScreen = HomeScreenRoute }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Filled.Videocam, contentDescription = "Camera") },
                                label = { Text("Camera") },
                                selected = currentScreen.route == CameraScreenRoute.route,
                                onClick = { 
                                    // Refresh confidence threshold when navigating to camera
                                    confidenceThreshold = SettingsManager.getConfidenceThreshold(context)
                                    currentScreen = CameraScreenRoute 
                                }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Filled.History, contentDescription = "History") },
                                label = { Text("History") },
                                selected = currentScreen.route == HistoryScreenRoute.route,
                                onClick = { currentScreen = HistoryScreenRoute }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Filled.Settings, contentDescription = "Settings") },
                                label = { Text("Settings") },
                                selected = currentScreen.route == SettingsScreenRoute.route,
                                onClick = { currentScreen = SettingsScreenRoute }
                            )
                        }
                    }
                ) { paddingValues ->
                    Box(modifier = Modifier.padding(paddingValues)) {
                        if (hasPermissions) {
                            when (currentScreen) {
                                HomeScreenRoute -> HomeScreen(
                                    pose = currentPose,
                                    score = currentScore,
                                    suggestion = currentSuggestion
                                )
                                CameraScreenRoute -> {
                                    // Ensure confidence threshold is always up-to-date when camera screen is shown
                                    LaunchedEffect(Unit) {
                                        val latestThreshold = SettingsManager.getConfidenceThreshold(context)
                                        if (latestThreshold != confidenceThreshold) {
                                            confidenceThreshold = latestThreshold
                                        }
                                    }
                                    
                                    val poseState by poseViewModel.poseState.collectAsState()
                                    
                                    Box(modifier = Modifier.fillMaxSize()) {
                                        when (cameraSource) {
                                            CameraSource.USB_CAMERA -> {
                                                if (cameraController == null) {
                                                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { 
                                                        Text("Initializing camera...") 
                                                    }
                                                } else {
                                                    val livePose = poseViewModel.currentOverrideLabel() ?: poseViewModel.getPoseDescription()
                                                    val liveScore = poseViewModel.getPostureScore()
                                                    val liveSuggestion = getPostureSuggestion(livePose)
                                                    CameraScreen(
                                                        controller = cameraController,
                                                        pose = livePose,
                                                        score = liveScore,
                                                        persons = poseState.persons,
                                                        suggestion = liveSuggestion,
                                                        fillCenter = false,
                                                        postureDetector = postureDetector,
                                                        poseViewModel = poseViewModel,
                                                        performanceMetrics = performanceMetrics,
                                                        postureMode = postureMode,
                                                        onRuntimeSwitch = { 
                                                            if (!isSwitchingRuntime) {
                                                                showRuntimeDialog = true
                                                            }
                                                        },
                                                        onCameraToggle = {
                                                            cameraSource = CameraSource.NETWORK_STREAM
                                                        },
                                                        showCameraOption = true,
                                                        cameraSourceLabel = "Switch to Webcam"
                                                    )
                                                }
                                            }
                                            CameraSource.NETWORK_STREAM -> {
                                                NetworkStreamScreen(
                                                    bitmap = networkStreamBitmap,
                                                    pose = poseViewModel.currentOverrideLabel() ?: poseViewModel.getPoseDescription(),
                                                    score = poseViewModel.getPostureScore(),
                                                    persons = poseState.persons,
                                                    suggestion = getPostureSuggestion(poseViewModel.currentOverrideLabel() ?: poseViewModel.getPoseDescription()),
                                                    postureDetector = postureDetector,
                                                    error = networkStreamError,
                                                    streamUrl = networkStreamUrl,
                                                    postureMode = postureMode,
                                                    onCameraToggle = {
                                                        cameraSource = CameraSource.USB_CAMERA
                                                    },
                                                    onServerSettings = { showNetworkSettings = true }
                                                )
                                            }
                                        }
                                    }
                                }
                                HistoryScreenRoute -> HistoryScreen(
                                    data = postureHistory
                                        .filter { it.score > 0 } // Ensure we only show valid scores
                                        .map { it.score to it.timestamp },
                                    sessionStartTime = sessionStartTime,
                                    sessionEndTime = sessionEndTime,
                                    currentSessionDuration = currentSessionDuration
                                )
                                SettingsScreenRoute -> {
                                    SettingsScreen(
                                        onNavigateToSetup = {
                                            currentScreen = ProfileSelectionScreenRoute
                                        },
                                        onNavigateToProfileSelection = {
                                            currentScreen = ProfileSelectionScreenRoute
                                        },
                                        onBack = {
                                            // Reload posture mode and confidence threshold when returning from settings
                                            postureMode = SettingsManager.getPostureMode(context)
                                            confidenceThreshold = SettingsManager.getConfidenceThreshold(context)
                                            currentScreen = HomeScreenRoute
                                        }
                                    )
                                }
                                ProfileSelectionScreenRoute -> {
                                    ProfileSelectionScreen(
                                        onProfileSelected = { selectedUserId ->
                                            SettingsManager.setUserId(context, selectedUserId)
                                            scope.launch {
                                                isPersonalizedModelLoaded = personalizedManager.loadModel(selectedUserId)
                                                val setupComplete = SettingsManager.isPersonalizedSetupComplete(context, selectedUserId)
                                                if (setupComplete) {
                                                    currentScreen = HomeScreenRoute
                                                } else {
                                                    currentScreen = PersonalizedSetupScreenRoute
                                                }
                                            }
                                        },
                                        onBack = {
                                            currentScreen = SettingsScreenRoute
                                        }
                                    )
                                }
                                PersonalizedSetupScreenRoute -> {
                                    when {
                                        isInitializingPersonalized -> {
                                            Box(
                                                modifier = Modifier.fillMaxSize(),
                                                contentAlignment = Alignment.Center
                                            ) {
                                                CircularProgressIndicator()
                                            }
                                        }
                                        personalizedInitError != null -> {
                                            Box(
                                                modifier = Modifier.fillMaxSize(),
                                                contentAlignment = Alignment.Center
                                            ) {
                                                Column(
                                                    horizontalAlignment = Alignment.CenterHorizontally,
                                                    verticalArrangement = Arrangement.spacedBy(12.dp)
                                                ) {
                                                    Text(
                                                        text = personalizedInitError ?: "Initialization failed",
                                                        color = MaterialTheme.colorScheme.error
                                                    )
                                                    Button(
                                                        onClick = {
                                                            personalizedInitError = null
                                                            scope.launch { ensurePersonalizedReady() }
                                                        }
                                                    ) {
                                                        Text("Retry")
                                                    }
                                                }
                                            }
                                        }
                                        else -> {
                                            PersonalizedSetupScreen(
                                                personalizedManager = personalizedManager,
                                                onCaptureReferencePosture = { onSuccess, onFailure ->
                                                    // Capture current posture angles
                                                    val currentPoseState = poseViewModel.poseState.value
                                                    android.util.Log.d("MainActivity", "Capturing reference: persons=${currentPoseState.persons.size}")

                                                    if (currentPoseState.persons.isNotEmpty()) {
                                                        val result = postureDetector.analyzePosture(currentPoseState.persons)
                                                        android.util.Log.d("MainActivity", "Posture result: ${result.posture}, angles=${result.angles}")

                                                        result.angles?.let { angles ->
                                                            android.util.Log.d(
                                                                "MainActivity",
                                                                "Calling callback with angles: neck=${angles.neckAngle}, back=${angles.backAngle}, legs=${angles.legsAngle}"
                                                            )
                                                            onSuccess(angles.neckAngle, angles.backAngle, angles.legsAngle)
                                                        } ?: run {
                                                            android.util.Log.e("MainActivity", "No angles available from posture detector")
                                                            onFailure()
                                                        }
                                                    } else {
                                                        android.util.Log.e("MainActivity", "No person detected when trying to capture reference")
                                                        onFailure()
                                                    }
                                                },
                                                onSetupComplete = {
                                                    // Reload model after setup
                                                    scope.launch {
                                                        val userId = SettingsManager.getUserId(context)
                                                        isPersonalizedModelLoaded = personalizedManager.loadModel(userId)
                                                        postureMode = SettingsManager.PostureDetectionMode.PERSONALIZED
                                                        SettingsManager.setPostureMode(context, postureMode)
                                                        currentScreen = SettingsScreenRoute
                                                    }
                                                },
                                                onBack = {
                                                    currentScreen = SettingsScreenRoute
                                                }
                                            )
                                        }
                                    }
                                }
                            }
                        } else {
                            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                Text("Please grant camera permissions to use the app.")
                            }
                        }
                    }
                }
                
                // Network settings dialog
                if (showNetworkSettings) {
                    NetworkSettingsDialog(
                        currentUrl = networkStreamUrl,
                        onDismiss = { showNetworkSettings = false },
                        onSave = { newUrl ->
                            networkStreamUrl = newUrl
                        }
                    )
                }
                
                // Runtime switching dialog
                if (showRuntimeDialog) {
                    RuntimeSwitchDialog(
                        currentRuntime = currentRuntime,
                        onDismiss = { showRuntimeDialog = false },
                        onRuntimeSelected = { newRuntime ->
                            if (isSwitchingRuntime) return@RuntimeSwitchDialog
                            showRuntimeDialog = false
                            isSwitchingRuntime = true
                            scope.launch {
                                try {
                                    Log.d("MainActivity", "Starting runtime switch to ${newRuntime.displayName}")
                                    val success = yoloPoseAnalyzer?.getDetector()?.switchRuntime(context, newRuntime) ?: false
                                    if (success) {
                                        Log.d("MainActivity", "Runtime switched successfully to ${newRuntime.displayName}")
                                    } else {
                                        Log.e("MainActivity", "Failed to switch runtime to ${newRuntime.displayName}")
                                    }
                                } catch (e: Exception) {
                                    Log.e("MainActivity", "Exception during runtime switch", e)
                                } finally {
                                    delay(500) // Small delay before allowing another switch
                                    isSwitchingRuntime = false
                                }
                            }
                        }
                    )
                }
            }
        }
    }

    companion object {
        private val CAMERAX_PERMISSIONS = arrayOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
        )
    }
}

@Composable
fun HomeScreen(
    pose: String,
    score: Int,
    suggestion: String = ""
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Spacer(modifier = Modifier.height(16.dp))
        
        // App Logo
        Image(
            painter = painterResource(id = R.drawable.pose_tracker_logo),
            contentDescription = "Pose Tracker Logo",
            modifier = Modifier
                .size(200.dp)
                .padding(bottom = 16.dp),
            contentScale = ContentScale.Fit
        )
        
        Text(
            "Welcome Back!",
            style = MaterialTheme.typography.headlineMedium,
        )
        Text(
            "Track your posture with QIDK Models",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 32.dp)
        )

        // Only show score circle if person is detected (score > 0)
        if (score > 0 && !pose.contains("No person detected", ignoreCase = true)) {
            // Main Score Display
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(220.dp) // Larger circle
                    .padding(bottom = 16.dp)
            ) {
                CircularProgressIndicator(
                    progress = { score / 100f },
                    modifier = Modifier.fillMaxSize(),
                    strokeWidth = 20.dp, // Thicker stroke
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                    color = when {
                        score > 80 -> Color(0xFF4CAF50)
                        score > 60 -> Color(0xFFFFC107)
                        else -> Color(0xFFF44336)
                    },
                    strokeCap = StrokeCap.Round // Rounded ends
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "$score",
                        style = MaterialTheme.typography.displayLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Score",
                        style = MaterialTheme.typography.titleMedium
                    )
                }
            }

            // Current Pose Text
            Text(
                text = pose,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 16.dp)
            )
        } else {
            // Show helpful message when no person detected
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        Icons.Filled.Videocam,
                        contentDescription = "Camera",
                        modifier = Modifier
                            .size(48.dp)
                            .padding(bottom = 12.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Step into frame",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        "Go to Camera tab to start tracking your posture",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            }
        }

        // Posture Improvement Suggestion
        if (suggestion.isNotEmpty() && !suggestion.contains("Perfect") && !suggestion.contains("Keep it up")) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(
                    containerColor = when {
                        pose.contains("No person detected") -> MaterialTheme.colorScheme.surfaceVariant
                        score < 60 -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.7f)
                        score < 80 -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f)
                        else -> MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.7f)
                    }
                )
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = "Suggestion",
                        modifier = Modifier.padding(end = 12.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = suggestion,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Good posture hint
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f)
            )
        ) {
            Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Info, contentDescription = "Info", modifier = Modifier.padding(end = 16.dp), tint = MaterialTheme.colorScheme.onTertiaryContainer)
                Column {
                    Text("Good posture is key!", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onTertiaryContainer)
                    Text("Aim for a score above 80 to maintain a healthy posture.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onTertiaryContainer)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}


@Composable
fun CameraScreen(
    controller: LifecycleCameraController,
    pose: String,
    score: Int,
    persons: List<PersonDetection>,
    suggestion: String,
    fillCenter: Boolean = true,
    postureDetector: PostureDetector,
    poseViewModel: PoseDetectionViewModel,
    performanceMetrics: PerformanceMetrics = PerformanceMetrics(),
    onRuntimeSwitch: () -> Unit = {},
    postureMode: SettingsManager.PostureDetectionMode = SettingsManager.PostureDetectionMode.STANDARD,
    onCameraToggle: (() -> Unit)? = null,
    showCameraOption: Boolean = false,
    cameraSourceLabel: String = "Switch to Webcam",
    onServerSettings: (() -> Unit)? = null,
    showServerOption: Boolean = false
) {
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    
    // Get live pose state for real-time calibration
    val livePoseState by poseViewModel.poseState.collectAsState()
    
    // Get current posture result for suggestions using live state
    val postureResult = remember(livePoseState.persons) {
        if (livePoseState.persons.isNotEmpty()) {
            postureDetector.analyzePosture(livePoseState.persons)
        } else null
    }
    
    Box(modifier = Modifier.fillMaxSize()) {
        // Snackbar host for calibration messages
        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 100.dp)
        )
        
        CameraPreview(
            controller = controller,
            modifier = Modifier.fillMaxSize()
        )
        SkeletonOverlay(
            persons = livePoseState.persons,
            modifier = Modifier.fillMaxSize(),
            fillCenter = fillCenter,
            showDebugInfo = false
        )
        
        // Top Section: Performance metrics only
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .padding(top = 12.dp, start = 12.dp, end = 12.dp)
        ) {
            // Performance metrics overlay at the top
            PerformanceOverlay(
                metrics = performanceMetrics,
                onRuntimeSwitch = onRuntimeSwitch,
                modifier = Modifier
                    .align(Alignment.End)
                    .padding(bottom = 8.dp),
                isCompact = true
            )
        }
        
        // Expandable Suggestions Panel on the right side
        if (postureResult != null) {
            ExpandableSuggestionsPanel(
                suggestions = postureResult.suggestions,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(top = 80.dp) // Below performance metrics
            )
        }
        
        // Tools Menu at top-left
        ToolsMenuPanel(
            postureDetector = postureDetector,
            persons = livePoseState.persons,
            snackbarHostState = snackbarHostState,
            scope = scope,
            showServerOption = showServerOption,
            onServerClick = onServerSettings,
            showCameraOption = showCameraOption,
            onCameraToggle = onCameraToggle,
            cameraSourceLabel = cameraSourceLabel,
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(start = 12.dp, top = 12.dp)
        )
        
        // Bottom section: Expandable stats panel + posture card
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.BottomCenter)
        ) {
            // Expandable stats panel (expands upward)
            ExpandableStatsPanel(postureResult = postureResult)
            
            // Main posture info card
            PostureInfoCard(pose = pose, score = score)
        }
    }
}

@Composable
fun HistoryScreen(
    data: List<Pair<Int, Long>>,
    sessionStartTime: Long?,
    sessionEndTime: Long?,
    currentSessionDuration: Long = 0L
) {
    val scrollState = rememberScrollState()
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Posture History", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 16.dp))
        
        // Session Status Indicator
        val (statusText, statusColor) = when {
            sessionStartTime == null -> "No Session Recorded" to MaterialTheme.colorScheme.outline
            sessionEndTime == null -> "Session Active" to MaterialTheme.colorScheme.primary
            else -> "Session Completed" to MaterialTheme.colorScheme.tertiary
        }
        
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp),
            shape = MaterialTheme.shapes.small,
            color = statusColor.copy(alpha = 0.15f)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .background(statusColor, shape = CircleShape)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    statusText,
                    style = MaterialTheme.typography.labelLarge,
                    color = statusColor
                )
            }
        }
        
        // Session Details Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    "Session Details",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                // Session start time
                if (sessionStartTime != null) {
                    Row(modifier = Modifier.padding(vertical = 4.dp)) {
                        Text(
                            "Started: ",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            formatTimestamp(sessionStartTime),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                
                // Session duration or end time
                val durationText = when {
                    sessionStartTime == null -> "No active session"
                    sessionEndTime == null -> {
                        val duration = currentSessionDuration / 1000
                        "Duration: ${formatDuration(duration)} (ongoing)"
                    }
                    else -> {
                        val duration = (sessionEndTime - sessionStartTime) / 1000
                        "Duration: ${formatDuration(duration)} (completed)"
                    }
                }
                
                Text(
                    durationText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
                
                // Data points info
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Data points: ${data.size}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp)
                    )
                    
                    if (data.isNotEmpty()) {
                        Text(
                            "Last updated: ${formatTimestamp(data.last().second)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        
        // Stats summary
        if (data.isNotEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.6f))
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        "Posture Statistics",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    
                    val avg = data.map { it.first }.average()
                    val max = data.maxOf { it.first }
                    val min = data.minOf { it.first }
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        StatItem("Average Score", avg.toInt(), getScoreColor(avg.toInt()))
                        StatItem("Highest Score", max, getScoreColor(max))
                        StatItem("Lowest Score", min, getScoreColor(min))
                    }
                }
            }
        }

        // Posture Graph Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    "Score Trend",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                if (data.size > 1) {
                    PostureGraph(data, modifier = Modifier.fillMaxWidth().height(250.dp))
                } else {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(200.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(
                                Icons.Filled.Info,
                                contentDescription = null,
                                modifier = Modifier
                                    .size(48.dp)
                                    .padding(bottom = 16.dp),
                                tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                            )
                            Text(
                                "Not enough data to generate graph.\nUse the camera to analyze your posture.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }
            }
        }
        
        // Recent entries list
        if (data.isNotEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "Recent Entries",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    
                    Column {
                        // Show only the last 5 entries in reverse chronological order (newest first)
                        data.takeLast(5).reversed().forEachIndexed { index, (score, timestamp) ->
                            if (index > 0) {
                                Divider(
                                    modifier = Modifier.padding(vertical = 8.dp),
                                    thickness = 0.5.dp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    formatTimestamp(timestamp),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Surface(
                                    shape = MaterialTheme.shapes.small,
                                    color = getScoreColor(score).copy(alpha = 0.2f),
                                    border = BorderStroke(1.dp, getScoreColor(score))
                                ) {
                                    Text(
                                        score.toString(),
                                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                                        color = getScoreColor(score),
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Help text for empty state
        if (data.isEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f))
            ) {
                Column(
                    modifier = Modifier
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = null,
                        modifier = Modifier
                            .size(36.dp)
                            .padding(bottom = 8.dp),
                        tint = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Text(
                        "How to Use Posture Analysis",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    Text(
                        "1. Go to the Camera tab\n" +
                        "2. Position yourself so your upper body is visible\n" +
                        "3. Maintain good posture for accurate readings\n" +
                        "4. Data will automatically be recorded here",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        textAlign = TextAlign.Start,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }
    }
}

// Helper function for timestamp formatting
private fun formatTimestamp(timestamp: Long): String {
    val sdf = SimpleDateFormat("hh:mm:ss a", Locale.getDefault())
    return sdf.format(Date(timestamp))
}

// Helper function to get appropriate color for score
private fun getScoreColor(score: Int): Color {
    return when {
        score >= 80 -> Color(0xFF4CAF50) // Green
        score >= 60 -> Color(0xFFFFC107) // Amber
        else -> Color(0xFFF44336)        // Red
    }
}

// Helper function to format duration
private fun formatDuration(seconds: Long): String {
    val hours = seconds / 3600
    val minutes = (seconds % 3600) / 60
    val remainingSeconds = seconds % 60
    
    return when {
        hours > 0 -> "${hours}h ${minutes}m ${remainingSeconds}s"
        minutes > 0 -> "${minutes}m ${remainingSeconds}s"
        else -> "${remainingSeconds}s"
    }
}

@Composable
fun PostureGraph(data: List<Pair<Int, Long>>, modifier: Modifier = Modifier) {
    val themeColors = MaterialTheme.colorScheme
    val lineColor = themeColors.primary
    val pointColor = themeColors.secondary
    val textColor = themeColors.onSurface
    val gradientStartColor = themeColors.primary.copy(alpha = 0.4f)
    val gradientEndColor = themeColors.primary.copy(alpha = 0.0f)
    val gridColor = themeColors.onSurface.copy(alpha = 0.2f)

    val timeFormat = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }
    
    // Filter to reasonable subset if too many points
    val displayData = remember(data) {
        if (data.size <= 20) data 
        else {
            // Sample evenly across the dataset
            val step = data.size / 20
            data.filterIndexed { index, _ -> index % step == 0 || index == data.lastIndex }
        }
    }

    Box(modifier = modifier) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val bottomPadding = 60f // for labels
            val leftPadding = 80f // for Y axis labels
            val topPadding = 20f // for breathing room
            val graphWidth = size.width - leftPadding - 20f
            val graphHeight = size.height - bottomPadding - topPadding

            if (displayData.size < 2) {
                // Handle case with not enough data
                return@Canvas
            }

            // Draw Y-axis labels and grid lines
            val yAxisLabels = listOf(0, 50, 80, 100)
            val textPaint = Paint().apply {
                color = textColor.toArgb()
                textSize = 28f
                textAlign = Paint.Align.RIGHT
            }
            
            // Draw X-axis line
            drawLine(
                color = gridColor,
                start = Offset(leftPadding, graphHeight + topPadding),
                end = Offset(size.width - 20f, graphHeight + topPadding),
                strokeWidth = 2f
            )
            
            // Draw Y-axis line
            drawLine(
                color = gridColor,
                start = Offset(leftPadding, topPadding),
                end = Offset(leftPadding, graphHeight + topPadding),
                strokeWidth = 2f
            )
            
            yAxisLabels.forEach { label ->
                val y = graphHeight + topPadding - (graphHeight * (label / 100f))
                drawContext.canvas.nativeCanvas.drawText(
                    label.toString(),
                    leftPadding - 10f,
                    y + (textPaint.fontMetrics.descent - textPaint.fontMetrics.ascent) / 3,
                    textPaint
                )
                drawLine(
                    color = gridColor,
                    start = Offset(leftPadding, y),
                    end = Offset(size.width - 20f, y),
                    strokeWidth = 1f,
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(8f, 8f), 0f)
                )
            }

            // Make points
            val points = displayData.mapIndexed { index, (value, _) ->
                val normalizedValue = value.coerceIn(0, 100)
                PointF(
                    leftPadding + (graphWidth * index / (displayData.size - 1)),
                    graphHeight + topPadding - (graphHeight * (normalizedValue / 100f))
                )
            }

            // Smooth line path
            val linePath = Path().apply {
                moveTo(points.first().x, points.first().y)
                for (i in 0 until points.size - 1) {
                    val p1 = points[i]
                    val p2 = points[i + 1]
                    val controlPoint1 = PointF((p1.x + p2.x) / 2f, p1.y)
                    val controlPoint2 = PointF((p1.x + p2.x) / 2f, p2.y)
                    cubicTo(
                        controlPoint1.x, controlPoint1.y,
                        controlPoint2.x, controlPoint2.y,
                        p2.x, p2.y
                    )
                }
            }

            // Gradient fill path
            val fillPath = Path().apply {
                moveTo(points.first().x, graphHeight + topPadding)
                lineTo(points.first().x, points.first().y)
                addPath(linePath)
                lineTo(points.last().x, graphHeight + topPadding)
                close()
            }

            // Draw gradient fill
            drawPath(
                path = fillPath,
                brush = Brush.verticalGradient(
                    colors = listOf(gradientStartColor, gradientEndColor),
                    startY = 0f,
                    endY = graphHeight + topPadding
                )
            )

            // Draw smooth line
            drawPath(
                path = linePath,
                color = lineColor,
                style = Stroke(width = 4f)
            )

            // Draw points - only show a reasonable number 
            val pointStep = if (points.size > 10) points.size / 10 else 1
            points.forEachIndexed { index, point ->
                if (index % pointStep == 0 || index == points.lastIndex) {
                    drawCircle(
                        color = pointColor,
                        radius = 6f,
                        center = Offset(point.x, point.y)
                    )
                    drawCircle(
                        color = Color.White,
                        radius = 3f,
                        center = Offset(point.x, point.y)
                    )
                }
            }

            // Draw timestamps - only a few for clarity
            val timestampTextPaint = Paint().apply {
                color = textColor.toArgb()
                textSize = 26f
                textAlign = Paint.Align.CENTER
            }
            
            // Choose evenly spaced points for timestamps (start, middle, end)
            val timestampIndices = when {
                displayData.size >= 3 -> listOf(0, displayData.size / 2, displayData.lastIndex)
                displayData.size == 2 -> listOf(0, displayData.lastIndex)
                else -> listOf(0)
            }
            
            timestampIndices.forEach { index ->
                val (_, timestamp) = displayData[index]
                val x = leftPadding + (graphWidth * index / (displayData.size - 1))
                drawContext.canvas.nativeCanvas.drawText(
                    timeFormat.format(Date(timestamp)),
                    x,
                    size.height - timestampTextPaint.fontMetrics.bottom,
                    timestampTextPaint
                )
            }
        }
    }
}

@Composable
private fun StatChip(label: String, value: Int) {
    Surface(
        shape = MaterialTheme.shapes.small,
        tonalElevation = 3.dp,
        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.6f)
    ) {
        Row(modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(label, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(end = 6.dp))
            Text(value.toString(), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun StatItem(label: String, value: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            value.toString(),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer
        )
    }
}

@Composable
fun PostureInfoCard(pose: String, score: Int) {
    Card(
        modifier = Modifier
            .fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.8f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(
                horizontalAlignment = Alignment.Start,
                modifier = Modifier.weight(1f) // Take available space, leave room for score
            ) {
                Text(
                    text = "CURRENT POSTURE",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.Normal,
                    letterSpacing = 1.2.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = pose,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 2, // Allow wrapping to 2 lines for long text
                    overflow = TextOverflow.Ellipsis,
                    lineHeight = 26.sp // Proper spacing between lines
                )
            }
            Spacer(modifier = Modifier.width(12.dp)) // Space between text and score
            Box(contentAlignment = Alignment.Center) {
                CircularProgressIndicator(
                    progress = { score / 100f },
                    modifier = Modifier.size(64.dp),
                    strokeWidth = 6.dp,
                    trackColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.1f),
                    color = when {
                        score > 80 -> Color(0xFF4CAF50) // Green
                        score > 60 -> Color(0xFFFFC107) // Amber
                        else -> Color(0xFFF44336)       // Red
                    }
                )
                Text(
                    text = "$score",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

/**
 * Expandable stats panel showing confidence score and posture angles
 */
@Composable
fun ExpandableStatsPanel(
    postureResult: PostureDetector.PostureResult?,
    modifier: Modifier = Modifier
) {
    var isExpanded by remember { mutableStateOf(false) }
    
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Expand/Collapse toggle button
        Surface(
            onClick = { isExpanded = !isExpanded },
            shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.9f),
            modifier = Modifier.width(120.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    if (isExpanded) "Hide Stats" else "Show Stats",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Icon(
                    imageVector = if (isExpanded) Icons.Filled.KeyboardArrowDown else Icons.Filled.KeyboardArrowUp,
                    contentDescription = if (isExpanded) "Collapse" else "Expand",
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        
        // Expandable content
        AnimatedVisibility(
            visible = isExpanded,
            enter = expandVertically(animationSpec = tween(200)) + fadeIn(),
            exit = shrinkVertically(animationSpec = tween(200)) + fadeOut()
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp),
                shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.95f)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                if (postureResult != null) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Confidence Score
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Filled.Speed,
                                    contentDescription = null,
                                    modifier = Modifier.size(20.dp),
                                    tint = MaterialTheme.colorScheme.primary
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "Confidence",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                            Text(
                                "${(postureResult.confidence * 100).toInt()}%",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = when {
                                    postureResult.confidence > 0.8f -> Color(0xFF4CAF50)
                                    postureResult.confidence > 0.5f -> Color(0xFFFFC107)
                                    else -> Color(0xFFF44336)
                                }
                            )
                        }
                        
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                        
                        // Angles Section
                        Text(
                            "POSTURE ANGLES",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            letterSpacing = 1.sp
                        )
                        
                        postureResult.angles?.let { angles ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceEvenly
                            ) {
                                AngleStatItem(
                                    label = "Neck",
                                    angle = angles.neckAngle
                                )
                                AngleStatItem(
                                    label = "Back",
                                    angle = angles.backAngle
                                )
                                AngleStatItem(
                                    label = "Legs",
                                    angle = angles.legsAngle
                                )
                            }
                        } ?: Text(
                            "Angles not available",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "No posture data available",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AngleStatItem(
    label: String,
    angle: Double
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.padding(8.dp)
    ) {
        Text(
            "${angle.toInt()}°",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface
        )
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/**
 * Tools menu panel at top-left with Calibrate, Reset, Camera, and Server options
 */
@Composable
fun ToolsMenuPanel(
    postureDetector: PostureDetector,
    persons: List<PersonDetection>,
    snackbarHostState: SnackbarHostState,
    scope: kotlinx.coroutines.CoroutineScope,
    onServerClick: (() -> Unit)? = null,
    showServerOption: Boolean = false,
    onCameraToggle: (() -> Unit)? = null,
    showCameraOption: Boolean = false,
    cameraSourceLabel: String = "Webcam",
    modifier: Modifier = Modifier
) {
    var isExpanded by remember { mutableStateOf(false) }
    
    Box(modifier = modifier) {
        Column(
            modifier = Modifier.align(Alignment.TopStart),
            horizontalAlignment = Alignment.Start
        ) {
            // Toggle button
            Surface(
                onClick = { isExpanded = !isExpanded },
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.95f),
                shadowElevation = 6.dp
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (isExpanded) Icons.Filled.Close else Icons.Filled.Build,
                        contentDescription = if (isExpanded) "Close menu" else "Open tools menu",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "Tools",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Icon(
                        imageVector = if (isExpanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            
            // Expanded menu
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically(animationSpec = tween(200)) + fadeIn(),
                exit = shrinkVertically(animationSpec = tween(150)) + fadeOut()
            ) {
                Card(
                    modifier = Modifier
                        .padding(top = 4.dp)
                        .widthIn(min = 180.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.98f)
                    ),
                    elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        // Calibrate option
                        Surface(
                            onClick = {
                                if (persons.isNotEmpty()) {
                                    val result = postureDetector.analyzePosture(persons)
                                    result.angles?.let { angles ->
                                        postureDetector.calibrate(
                                            angles.neckAngle,
                                            angles.backAngle,
                                            angles.legsAngle
                                        )
                                        scope.launch {
                                            snackbarHostState.showSnackbar(
                                                message = "✓ Calibrated! Sit in this posture for best results",
                                                duration = SnackbarDuration.Short
                                            )
                                        }
                                    }
                                } else {
                                    scope.launch {
                                        snackbarHostState.showSnackbar(
                                            message = "No person detected. Please be visible in camera.",
                                            duration = SnackbarDuration.Short
                                        )
                                    }
                                }
                                isExpanded = false
                            },
                            shape = RoundedCornerShape(8.dp),
                            color = Color.Transparent
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(32.dp)
                                        .background(
                                            color = Color(0xFF6366F1).copy(alpha = 0.15f),
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        painter = painterResource(android.R.drawable.ic_menu_camera),
                                        contentDescription = null,
                                        tint = Color(0xFF6366F1),
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Column {
                                    Text(
                                        "Calibrate",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                    Text(
                                        "Set current posture as reference",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                        
                        // Reset option
                        Surface(
                            onClick = {
                                postureDetector.resetToDefaults()
                                scope.launch {
                                    snackbarHostState.showSnackbar(
                                        message = "↺ Reset to default posture settings",
                                        duration = SnackbarDuration.Short
                                    )
                                }
                                isExpanded = false
                            },
                            shape = RoundedCornerShape(8.dp),
                            color = Color.Transparent
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(32.dp)
                                        .background(
                                            color = Color(0xFF10B981).copy(alpha = 0.15f),
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        painter = painterResource(android.R.drawable.ic_menu_revert),
                                        contentDescription = null,
                                        tint = Color(0xFF10B981),
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Column {
                                    Text(
                                        "Reset",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                    Text(
                                        "Restore default settings",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                        
                        // Camera toggle option (only shown when applicable)
                        if (showCameraOption && onCameraToggle != null) {
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                            )
                            
                            Surface(
                                onClick = {
                                    onCameraToggle()
                                    isExpanded = false
                                },
                                shape = RoundedCornerShape(8.dp),
                                color = Color.Transparent
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(32.dp)
                                            .background(
                                                color = Color(0xFF8B5CF6).copy(alpha = 0.15f),
                                                shape = CircleShape
                                            ),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = Icons.Filled.Videocam,
                                            contentDescription = null,
                                            tint = Color(0xFF8B5CF6),
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Column {
                                        Text(
                                            cameraSourceLabel,
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        Text(
                                            "Switch camera source",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                        
                        // Server option (only shown when applicable)
                        if (showServerOption && onServerClick != null) {
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                            )
                            
                            Surface(
                                onClick = {
                                    onServerClick()
                                    isExpanded = false
                                },
                                shape = RoundedCornerShape(8.dp),
                                color = Color.Transparent
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(32.dp)
                                            .background(
                                                color = Color(0xFF3B82F6).copy(alpha = 0.15f),
                                                shape = CircleShape
                                            ),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = Icons.Filled.Wifi,
                                            contentDescription = null,
                                            tint = Color(0xFF3B82F6),
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Column {
                                        Text(
                                            "Server Settings",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        Text(
                                            "Configure stream URL",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Expandable suggestions panel on the right side of the screen
 * Expands to the left when tapped to show posture improvement suggestions
 */
@Composable
fun ExpandableSuggestionsPanel(
    suggestions: List<String>,
    modifier: Modifier = Modifier
) {
    var isExpanded by remember { mutableStateOf(false) }
    
    // Don't show if no suggestions
    if (suggestions.isEmpty()) return
    
    Box(
        modifier = modifier
    ) {
        Row(
            modifier = Modifier.align(Alignment.TopEnd),
            verticalAlignment = Alignment.Top
        ) {
            // Expanded content - slides in from right
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandHorizontally(
                    animationSpec = tween(250),
                    expandFrom = Alignment.End
                ) + fadeIn(animationSpec = tween(200)),
                exit = shrinkHorizontally(
                    animationSpec = tween(200),
                    shrinkTowards = Alignment.End
                ) + fadeOut(animationSpec = tween(150))
            ) {
                Card(
                    modifier = Modifier
                        .widthIn(max = 280.dp)
                        .padding(end = 4.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.95f)
                    ),
                    elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Header
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Lightbulb,
                                contentDescription = null,
                                tint = Color(0xFFFB923C),
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "Suggestions",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                        )
                        
                        // Suggestions list
                        suggestions.forEachIndexed { index, suggestion ->
                            Row(
                                verticalAlignment = Alignment.Top,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(20.dp)
                                        .background(
                                            color = Color(0xFFFB923C).copy(alpha = 0.15f),
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        "${index + 1}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFFFB923C)
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    suggestion,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    lineHeight = 18.sp
                                )
                            }
                        }
                    }
                }
            }
            
            // Toggle button - always visible (simple and professional)
            Surface(
                onClick = { isExpanded = !isExpanded },
                shape = RoundedCornerShape(
                    topStart = 16.dp,
                    bottomStart = 16.dp,
                    topEnd = 6.dp,
                    bottomEnd = 6.dp
                ),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.95f),
                shadowElevation = 4.dp
            ) {
                Column(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (isExpanded) {
                        // Simple arrow when expanded
                        Text(
                            "›",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        // Clean badge with count when collapsed - larger size
                        Text(
                            "${suggestions.size}",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                            fontSize = 24.sp
                        )
                        Text(
                            "tips",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }
    }
}

// Helper function to get posture improvement suggestions
private fun getPostureSuggestion(posture: String): String {
    val p = posture.lowercase()
    return when {
        p.contains("no person") -> "Step into frame"
        p.contains("excellent") -> "Perfect posture!"
        p.contains("hunched") || p.contains("hunch") -> "Straighten back"
        p.contains("neck forward") || p.contains("neck bent") -> "Pull chin back"
        p.contains("looking down") || p.contains("neck down") -> "Lift head up"
        p.contains("recline") || p.contains("leaning back") -> "Sit upright"
        p.contains("fair posture") -> "Adjust shoulders"
    p.contains("poor posture") -> "Straighten spine"
        p.contains("very poor") -> "Reset posture"
        else -> "Keep it up!"
    }
}
@Composable
fun NetworkStreamScreen(
    bitmap: Bitmap?,
    pose: String,
    score: Int,
    persons: List<PersonDetection>,
    suggestion: String,
    postureDetector: PostureDetector,
    error: String?,
    streamUrl: String,
    postureMode: SettingsManager.PostureDetectionMode = SettingsManager.PostureDetectionMode.STANDARD,
    onCameraToggle: (() -> Unit)? = null,
    onServerSettings: (() -> Unit)? = null
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    
    val postureResult = remember(persons) {
        if (persons.isNotEmpty()) {
            postureDetector.analyzePosture(persons)
        } else null
    }
    
    Box(modifier = Modifier.fillMaxSize()) {
        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 100.dp)
        )
        
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black)
        )
        
        if (bitmap != null) {
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = "Network stream",
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.Fit
            )
            
            SkeletonOverlay(
                persons = persons,
                modifier = Modifier.fillMaxSize(),
                fillCenter = false,
                showDebugInfo = false
            )
        } else {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    if (error != null) {
                        Icon(
                            imageVector = Icons.Filled.Info,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = Color.Red
                        )
                        Text(
                            "Connection Error",
                            style = MaterialTheme.typography.titleLarge,
                            color = Color.White
                        )
                        Text(
                            error,
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color.White.copy(alpha = 0.7f),
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 32.dp)
                        )
                        Text(
                            "URL: $streamUrl",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.5f),
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 32.dp)
                        )
                    } else {
                        CircularProgressIndicator(color = Color.White)
                        Text(
                            "Connecting to stream...",
                            style = MaterialTheme.typography.titleMedium,
                            color = Color.White
                        )
                        Text(
                            streamUrl,
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.7f),
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 32.dp)
                        )
                    }
                }
            }
        }
        
        // Expandable Suggestions Panel on the right side
        if (postureResult != null) {
            ExpandableSuggestionsPanel(
                suggestions = postureResult.suggestions,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(top = 12.dp)
            )
        }

        // Tools Menu Panel at top-left (with camera toggle and server options)
        ToolsMenuPanel(
            postureDetector = postureDetector,
            persons = persons,
            snackbarHostState = snackbarHostState,
            scope = scope,
            showServerOption = onServerSettings != null,
            onServerClick = onServerSettings,
            showCameraOption = onCameraToggle != null,
            onCameraToggle = onCameraToggle,
            cameraSourceLabel = "Switch to Camera",
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(start = 12.dp, top = 12.dp)
        )
        
        // Bottom section: Expandable stats panel + posture card
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.BottomCenter)
                .padding(horizontal = 16.dp)
        ) {
            // Expandable stats panel (expands upward)
            ExpandableStatsPanel(postureResult = postureResult)
            
            // Posture card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.95f)
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "POSTURE",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontWeight = FontWeight.SemiBold,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            pose,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                            lineHeight = 24.sp
                        )
                    }
                    
                    Spacer(modifier = Modifier.width(16.dp))
                    
                    Box(contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(
                            progress = { score / 100f },
                            modifier = Modifier.size(72.dp),
                            strokeWidth = 7.dp,
                            trackColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.1f),
                            color = when {
                                score > 80 -> Color(0xFF4CAF50)
                                score > 60 -> Color(0xFFFFC107)
                                else -> Color(0xFFF44336)
                            }
                        )
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                "$score",
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                "score",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun NetworkSettingsDialog(
    currentUrl: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var urlInput by remember { mutableStateOf(currentUrl) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Network Stream Settings") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Enter the MJPEG stream URL from your webcam server",
                    style = MaterialTheme.typography.bodyMedium
                )
                OutlinedTextField(
                    value = urlInput,
                    onValueChange = { urlInput = it },
                    label = { Text("Stream URL") },
                    placeholder = { Text("http://10.1.40.98:5000/video_feed") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = false,
                    maxLines = 3
                )
                Text(
                    text = "Format: http://IP:PORT/video_feed",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            Button(onClick = {
                onSave(urlInput.trim())
                onDismiss()
            }) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
