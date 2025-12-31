package com.example.eswproject

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Personalized Mode Setup Screen
 * Guides user through capturing reference posture and training model
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PersonalizedSetupScreen(
    personalizedManager: PersonalizedPostureManager,
    onCaptureReferencePosture: (onSuccess: (Double, Double, Double) -> Unit, onFailure: () -> Unit) -> Unit,
    onSetupComplete: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    var setupStep by remember { mutableIntStateOf(0) }
    var isProcessing by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var successMessage by remember { mutableStateOf<String?>(null) }
    
    var capturedNeck by remember { mutableDoubleStateOf(0.0) }
    var capturedBack by remember { mutableDoubleStateOf(0.0) }
    var capturedLegs by remember { mutableDoubleStateOf(0.0) }
    
    val userId = SettingsManager.getUserId(context)
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Personalized Mode Setup") },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = !isProcessing) {
                        Icon(Icons.Default.ArrowBack, "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Progress Indicator
            LinearProgressIndicator(
                progress = { (setupStep + 1) / 4f },
                modifier = Modifier.fillMaxWidth()
            )
            
            Text(
                "Step ${setupStep + 1} of 4",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Step Content
            when (setupStep) {
                0 -> WelcomeStep(userId, onNext = { setupStep = 1 })
                1 -> CaptureReferenceStep(
                    isProcessing = isProcessing,
                    onCapture = {
                        isProcessing = true
                        errorMessage = null
                        successMessage = null
                        onCaptureReferencePosture(
                            { neck, back, legs ->
                                capturedNeck = neck
                                capturedBack = back
                                capturedLegs = legs
                                successMessage = "Reference posture captured successfully!"
                                isProcessing = false
                                setupStep = 2
                            },
                            {
                                errorMessage = "No person detected! Please ensure you're visible in the camera."
                                isProcessing = false
                            }
                        )
                    }
                )
                2 -> SaveReferenceStep(
                    userId = userId,
                    neckAngle = capturedNeck,
                    backAngle = capturedBack,
                    legsAngle = capturedLegs,
                    isProcessing = isProcessing,
                    onSave = {
                        isProcessing = true
                        errorMessage = null
                        scope.launch {
                            val success = personalizedManager.saveReferencePosture(
                                userId, capturedNeck, capturedBack, capturedLegs
                            )
                            isProcessing = false
                            if (success) {
                                successMessage = "Reference posture saved!"
                                setupStep = 3
                            } else {
                                errorMessage = "Failed to save reference posture"
                            }
                        }
                    }
                )
                3 -> TrainModelStep(
                    userId = userId,
                    isProcessing = isProcessing,
                    onTrain = {
                        isProcessing = true
                        errorMessage = null
                        successMessage = null
                        scope.launch {
                            val success = personalizedManager.trainModel(userId)
                            isProcessing = false
                            if (success) {
                                SettingsManager.setPersonalizedSetupComplete(context, true, userId)
                                successMessage = "Model training complete!"
                                delay(1500)
                                onSetupComplete()
                            } else {
                                errorMessage = "Model training failed. Please try again."
                            }
                        }
                    }
                )
            }
            
            // Error/Success Messages
            AnimatedVisibility(visible = errorMessage != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Error,
                            "Error",
                            tint = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            errorMessage ?: "",
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
            
            AnimatedVisibility(visible = successMessage != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF4CAF50).copy(alpha = 0.1f)
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.CheckCircle,
                            "Success",
                            tint = Color(0xFF4CAF50)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            successMessage ?: "",
                            color = Color(0xFF1B5E20)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun WelcomeStep(userId: String, onNext: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(
            Icons.Default.Person,
            "Welcome",
            modifier = Modifier
                .size(64.dp)
                .align(Alignment.CenterHorizontally)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primaryContainer)
                .padding(12.dp),
            tint = MaterialTheme.colorScheme.onPrimaryContainer
        )
        
        Text(
            "Welcome to Personalized Mode",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Setup for: $userId",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold
                )
                
                Text(
                    "This setup will:",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                
                SetupBulletPoint("1. Capture your ideal sitting posture")
                SetupBulletPoint("2. Train a machine learning model for your body")
                SetupBulletPoint("3. Provide personalized posture corrections")
                
                Divider()
                
                Text(
                    "⏱️ Takes approximately 2-3 minutes",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        
        Button(
            onClick = onNext,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Start Setup")
            Spacer(modifier = Modifier.width(8.dp))
            Icon(Icons.Default.ArrowForward, "Next")
        }
    }
}

@Composable
fun CaptureReferenceStep(
    isProcessing: Boolean,
    onCapture: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            "Capture Reference Posture",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Instructions:",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold
                )
                
                SetupBulletPoint("Sit in your IDEAL posture (back straight, feet flat)")
                SetupBulletPoint("Ensure your full body is visible in camera")
                SetupBulletPoint("Stay still for 3 seconds during capture")
                SetupBulletPoint("Good lighting is essential")
            }
        }
        
        Button(
            onClick = onCapture,
            enabled = !isProcessing,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isProcessing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Capturing...")
            } else {
                Icon(Icons.Default.Camera, "Capture")
                Spacer(modifier = Modifier.width(8.dp))
                Text("Capture My Posture")
            }
        }
    }
}

@Composable
fun SaveReferenceStep(
    userId: String,
    neckAngle: Double,
    backAngle: Double,
    legsAngle: Double,
    isProcessing: Boolean,
    onSave: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            "Confirm Reference Angles",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Captured Angles:",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                
                AngleDisplay("Neck", neckAngle)
                AngleDisplay("Back", backAngle)
                AngleDisplay("Legs", legsAngle)
            }
        }
        
        Button(
            onClick = onSave,
            enabled = !isProcessing,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isProcessing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Saving...")
            } else {
                Icon(Icons.Default.Save, "Save")
                Spacer(modifier = Modifier.width(8.dp))
                Text("Save Reference")
            }
        }
    }
}

@Composable
fun TrainModelStep(
    userId: String,
    isProcessing: Boolean,
    onTrain: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            "Train Personalized Model",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Final Step!",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold
                )
                
                Text(
                    "The app will now train a LightGBM machine learning model using:",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                SetupBulletPoint("Your captured reference posture")
                SetupBulletPoint("678 baseline training samples")
                SetupBulletPoint("Personalized deviation calculations")
                
                Divider()
                
                Text(
                    "⏱️ Training takes 10-30 seconds",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        
        Button(
            onClick = onTrain,
            enabled = !isProcessing,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isProcessing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Training Model...")
            } else {
                Icon(Icons.Default.Psychology, "Train")
                Spacer(modifier = Modifier.width(8.dp))
                Text("Train Model")
            }
        }
    }
}

@Composable
fun SetupBulletPoint(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            "• ",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
fun AngleDisplay(label: String, angle: Double) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            "$label:",
            style = MaterialTheme.typography.bodyMedium
        )
        Text(
            "${"%.1f".format(angle)}°",
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary
        )
    }
}
