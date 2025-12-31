package com.example.eswproject

/**
 * Example integration showing how to use the new pose detection backend
 * Add this code to your existing MainActivity.kt
 */

/*
// Add these imports to your MainActivity.kt:
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.runtime.collectAsState

// Add this in your MainActivity onCreate() after creating cameraController:

// Initialize pose detection ViewModel
val poseViewModel: PoseDetectionViewModel = viewModel()
val poseState by poseViewModel.poseState.collectAsState()
val backendInfo by poseViewModel.backendInfo.collectAsState()

// Initialize backend when the app starts
LaunchedEffect(Unit) {
    poseViewModel.initializeBackend(context)
}

// Example of how to integrate real pose detection with camera frames:
// (This would replace your demo data simulation)

LaunchedEffect(backendInfo.isInitialized) {
    if (backendInfo.isInitialized) {
        // Start processing camera frames for pose detection
        // You would set up ImageAnalysis here to capture frames and pass to poseViewModel.detectPose()
        Log.d("MainActivity", "Pose detection backend ready: ${backendInfo.currentBackend}")
    }
}

// Update your screen data to use real pose detection results:
val currentPose = if (poseState.persons.isNotEmpty()) {
    poseViewModel.getPoseDescription()
} else {
    "No pose detected"
}

val currentScore = poseViewModel.getPostureScore()

// In your screen components, you can now use:
// - currentPose instead of demoData.last().first
// - currentScore instead of demoData.last().second
// - poseState.persons for drawing pose overlays
// - backendInfo.currentBackend to show which backend is active

*/

/**
 * Backend Status Composable - Add this to show backend information
 */
/*
@Composable
fun BackendStatusCard(backendInfo: BackendInfo) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "ML Backend Status",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            
            Row {
                Text("Status: ")
                Text(
                    text = if (backendInfo.isInitialized) "✅ Ready" else "❌ Not Ready",
                    color = if (backendInfo.isInitialized) Color.Green else Color.Red
                )
            }
            
            if (backendInfo.isInitialized) {
                Row {
                    Text("Backend: ")
                    Text(
                        text = when (backendInfo.currentBackend) {
                            MLBackend.SNPE_DLC -> "🚀 SNPE/DLC (Optimized)"
                            MLBackend.TENSORFLOW_LITE -> "📱 TensorFlow Lite"
                        },
                        fontWeight = FontWeight.Medium
                    )
                }
                
                Row {
                    Text("Device: ")
                    Text(
                        text = if (backendInfo.isQualcommDevice) "Qualcomm Snapdragon" else "Standard Android",
                        fontStyle = FontStyle.Italic
                    )
                }
                
                Row {
                    Text("Performance: ")
                    Text(
                        text = when (backendInfo.performanceTier) {
                            PerformanceTier.HIGH -> "🔥 High (DSP/NPU)"
                            PerformanceTier.MEDIUM -> "⚡ Medium (GPU)"
                            PerformanceTier.LOW -> "🐌 Basic (CPU)"
                        }
                    )
                }
            }
            
            if (backendInfo.error != null) {
                Text(
                    text = "Error: ${backendInfo.error}",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
*/

/**
 * Performance Metrics Composable - Shows inference timing
 */
/*
@Composable  
fun PerformanceMetrics(poseState: PoseDetectionState) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Performance Metrics",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            
            Row {
                Text("Inference Time: ")
                Text(
                    text = "${poseState.inferenceTime}ms",
                    fontWeight = FontWeight.Medium,
                    color = when {
                        poseState.inferenceTime < 50 -> Color.Green
                        poseState.inferenceTime < 100 -> Color(0xFFFF9800)
                        else -> Color.Red
                    }
                )
            }
            
            Row {
                Text("Persons Detected: ")
                Text(
                    text = "${poseState.persons.size}",
                    fontWeight = FontWeight.Medium
                )
            }
            
            if (poseState.lastUpdate > 0) {
                val timeSinceUpdate = (System.currentTimeMillis() - poseState.lastUpdate) / 1000
                Row {
                    Text("Last Update: ")
                    Text(
                        text = "${timeSinceUpdate}s ago",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
            
            if (poseState.isProcessing) {
                Row {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Processing...")
                }
            }
        }
    }
}
*/