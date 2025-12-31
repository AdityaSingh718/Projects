package com.example.eswproject

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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Settings Screen with Posture Detection Mode Selection
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onNavigateToSetup: () -> Unit,
    onNavigateToProfileSelection: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var currentMode by remember { 
        mutableStateOf(SettingsManager.getPostureMode(context))
    }
    var userId by remember {
        mutableStateOf(SettingsManager.getUserId(context))
    }
    var isSetupComplete by remember {
        mutableStateOf(SettingsManager.isPersonalizedSetupComplete(context, userId))
    }
    var knownUsers by remember {
        mutableStateOf(SettingsManager.getPersonalizedUsers(context))
    }
    
    var showUserIdDialog by remember { mutableStateOf(false) }
    var showInfoDialog by remember { mutableStateOf(false) }
    var confidenceThreshold by remember {
        mutableStateOf(SettingsManager.getConfidenceThreshold(context))
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
            // Mode Selection Section
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Posture Detection Mode",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        IconButton(onClick = { showInfoDialog = true }) {
                            Icon(Icons.Default.Info, "Info", tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                    
                    Divider()
                    
                    // Standard Mode Option
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = currentMode == SettingsManager.PostureDetectionMode.STANDARD,
                            onClick = {
                                currentMode = SettingsManager.PostureDetectionMode.STANDARD
                                SettingsManager.setPostureMode(context, currentMode)
                            }
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Standard Mode",
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                "Rule-based posture detection with fixed thresholds",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    
                    // Personalized Mode Option
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = currentMode == SettingsManager.PostureDetectionMode.PERSONALIZED,
                            onClick = {
                                currentMode = SettingsManager.PostureDetectionMode.PERSONALIZED
                                SettingsManager.setPostureMode(context, currentMode)
                            }
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    "Personalized Mode",
                                    style = MaterialTheme.typography.bodyLarge,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                if (isSetupComplete) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        "Setup Complete",
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            }
                            Text(
                                "LightGBM ML model trained on your unique posture",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
            
            // Confidence Threshold Section
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "Detection Confidence Threshold",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Text(
                        "Minimum confidence required for keypoint detection. Higher values mean stricter filtering but may reject valid poses in poor lighting.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    
                    Divider()
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Threshold",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium
                        )
                        Text(
                            "${(confidenceThreshold * 100).toInt()}%",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    
                    Slider(
                        value = confidenceThreshold,
                        onValueChange = { confidenceThreshold = it },
                        onValueChangeFinished = {
                            SettingsManager.setConfidenceThreshold(context, confidenceThreshold)
                        },
                        valueRange = SettingsManager.MIN_CONFIDENCE_THRESHOLD..SettingsManager.MAX_CONFIDENCE_THRESHOLD,
                        steps = 19, // Creates steps of 5% (0%, 5%, 10%, ... 100%)
                        modifier = Modifier.fillMaxWidth()
                    )
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "${(SettingsManager.MIN_CONFIDENCE_THRESHOLD * 100).toInt()}%",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "Default: ${(SettingsManager.DEFAULT_CONFIDENCE_THRESHOLD * 100).toInt()}%",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            "${(SettingsManager.MAX_CONFIDENCE_THRESHOLD * 100).toInt()}%",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    // Reset button
                    if (confidenceThreshold != SettingsManager.DEFAULT_CONFIDENCE_THRESHOLD) {
                        OutlinedButton(
                            onClick = {
                                confidenceThreshold = SettingsManager.DEFAULT_CONFIDENCE_THRESHOLD
                                SettingsManager.setConfidenceThreshold(context, confidenceThreshold)
                            },
                            modifier = Modifier.align(Alignment.End)
                        ) {
                            Text("Reset to Default")
                        }
                    }
                }
            }
            
            // Personalized Mode Settings
            if (currentMode == SettingsManager.PostureDetectionMode.PERSONALIZED) {
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
                            "Personalized Settings",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        
                        Divider()
                        
                        // Current User ID
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    "User ID",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    userId,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                            TextButton(onClick = {
                                knownUsers = SettingsManager.getPersonalizedUsers(context)
                                onNavigateToProfileSelection()
                            }) {
                                Text("Change")
                            }
                        }
                        
                        // Setup Status
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    "Setup Status",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                                Text(
                                    if (isSetupComplete) "Complete" else "Incomplete",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (isSetupComplete) 
                                        MaterialTheme.colorScheme.primary 
                                    else 
                                        MaterialTheme.colorScheme.error
                                )
                            }
                            if (!isSetupComplete) {
                                Button(onClick = onNavigateToSetup) {
                                    Text("Setup Now")
                                }
                            } else {
                                OutlinedButton(onClick = onNavigateToSetup) {
                                    Text("Re-calibrate")
                                }
                            }
                        }
                    }
                }
                
                // Warning Card
                if (!isSetupComplete) {
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
                                Icons.Default.Warning,
                                "Warning",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(24.dp)
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Text(
                                "Personalized mode requires setup. Please complete the setup to use this feature.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                        }
                    }
                }
            }
        }
    }
    
    // User ID Dialog
    if (showUserIdDialog) {
        UserSelectionSheet(
            currentUserId = userId,
            users = knownUsers,
            onDismiss = { showUserIdDialog = false },
            onAddUser = { newUser ->
                val trimmed = newUser.trim()
                if (trimmed.isNotEmpty()) {
                    knownUsers = SettingsManager.addPersonalizedUser(context, trimmed)
                    SettingsManager.setUserId(context, trimmed)
                    SettingsManager.setPersonalizedSetupComplete(context, false, trimmed)
                    userId = trimmed
                    isSetupComplete = false
                    showUserIdDialog = false
                }
            },
            onUserSelected = { selected ->
                SettingsManager.setUserId(context, selected)
                userId = selected
                isSetupComplete = SettingsManager.isPersonalizedSetupComplete(context, selected)
                knownUsers = SettingsManager.getPersonalizedUsers(context)
                showUserIdDialog = false
            }
        )
    }
    
    // Info Dialog
    if (showInfoDialog) {
        AlertDialog(
            onDismissRequest = { showInfoDialog = false },
            title = { Text("Posture Detection Modes") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        "Standard Mode:",
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        "Uses predefined rules and thresholds to detect posture. Works immediately without setup.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Text(
                        "Personalized Mode:",
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        "Uses a LightGBM machine learning model trained specifically for your body. Requires:\n" +
                        "1. Capturing your reference posture (sitting straight)\n" +
                        "2. Training the model (one-time setup)\n\n" +
                        "Provides more accurate results tailored to your unique posture.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            },
            confirmButton = {
                Button(onClick = { showInfoDialog = false }) {
                    Text("Got it")
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun UserSelectionSheet(
    currentUserId: String,
    users: List<String>,
    onDismiss: () -> Unit,
    onAddUser: (String) -> Unit,
    onUserSelected: (String) -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var newUserName by remember { mutableStateOf("") }
    val canCreate = newUserName.trim().length >= 3

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        dragHandle = { BottomSheetDefaults.DragHandle() }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                "Choose your profile",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            Text(
                "Switch between personalized profiles or create a new one for each teammate using the app.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (users.isEmpty()) {
                Text(
                    "No profiles found yet. Add your first profile below to get started.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    users.forEach { profile ->
                        UserProfileCard(
                            name = profile,
                            selected = profile == currentUserId,
                            onClick = { onUserSelected(profile) }
                        )
                    }
                }
            }

            Divider()

            Text(
                "Add a new profile",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            OutlinedTextField(
                value = newUserName,
                onValueChange = { newUserName = it },
                label = { Text("Profile name") },
                placeholder = { Text("e.g. Alex, Desk 2") },
                singleLine = true
            )
            Button(
                onClick = {
                    onAddUser(newUserName)
                    newUserName = ""
                },
                enabled = canCreate,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Add & Switch")
            }
        }
    }
}

@Composable
private fun UserProfileCard(
    name: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    val containerColor = if (selected) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val avatarColor: Color
    val avatarTextColor: Color
    if (selected) {
        avatarColor = MaterialTheme.colorScheme.primary
        avatarTextColor = MaterialTheme.colorScheme.onPrimary
    } else {
        avatarColor = MaterialTheme.colorScheme.secondaryContainer
        avatarTextColor = MaterialTheme.colorScheme.onSecondaryContainer
    }

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.elevatedCardColors(containerColor = containerColor)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(avatarColor),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                    style = MaterialTheme.typography.titleMedium,
                    color = avatarTextColor,
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    if (selected) "Active profile" else "Tap to switch to this profile",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Icon(
                imageVector = if (selected) Icons.Default.CheckCircle else Icons.Default.ArrowForward,
                contentDescription = null,
                tint = if (selected)
                    MaterialTheme.colorScheme.primary
                else
                    MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
