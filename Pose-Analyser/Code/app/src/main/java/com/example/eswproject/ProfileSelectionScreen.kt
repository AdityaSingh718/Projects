package com.example.eswproject

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.RemoveCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.rememberAsyncImagePainter

/**
 * Netflix-style profile selection screen for Personalized Mode
 */
@Composable
fun ProfileSelectionScreen(
    onProfileSelected: (String) -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var profiles by remember { mutableStateOf(SettingsManager.getPersonalizedUsers(context)) }
    val currentUserId = remember { SettingsManager.getUserId(context) }
    var showAddDialog by remember { mutableStateOf(false) }
    var isManagementMode by remember { mutableStateOf(false) }
    var profileToDelete by remember { mutableStateOf<String?>(null) }
    var profileToEdit by remember { mutableStateOf<String?>(null) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF0A0A0A),
                        Color(0xFF1A1A1A)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))
            
            // Title
            Text(
                if (isManagementMode) "Manage Profiles" else "Who's analyzing posture?",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                fontSize = 28.sp
            )
            
            Spacer(modifier = Modifier.height(32.dp))
            
            // Profile Grid
            LazyVerticalGrid(
                columns = GridCells.Adaptive(minSize = 120.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterHorizontally),
                verticalArrangement = Arrangement.spacedBy(24.dp),
                contentPadding = PaddingValues(horizontal = 16.dp)
            ) {
                // Existing profiles
                items(profiles) { profile ->
                    ProfileCard(
                        name = profile,
                        isCurrentUser = profile == currentUserId,
                        isManagementMode = isManagementMode,
                        onClick = { 
                            if (!isManagementMode) {
                                onProfileSelected(profile)
                            }
                        },
                        onDelete = { profileToDelete = profile },
                        onEditPhoto = { profileToEdit = profile }
                    )
                }
                
                // Add Profile card
                item {
                    AddProfileCard(
                        onClick = { showAddDialog = true }
                    )
                }
            }
            
            Spacer(modifier = Modifier.weight(1f))
            
            // Manage Profiles / Done button
            OutlinedButton(
                onClick = { 
                    if (isManagementMode) {
                        isManagementMode = false
                    } else {
                        isManagementMode = true
                    }
                },
                modifier = Modifier
                    .padding(bottom = 32.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                ),
                border = ButtonDefaults.outlinedButtonBorder.copy(
                    width = 1.5.dp,
                    brush = SolidColor(Color.White.copy(alpha = 0.5f))
                )
            ) {
                Text(
                    if (isManagementMode) "DONE" else "MANAGE PROFILES",
                    style = MaterialTheme.typography.labelLarge,
                    letterSpacing = 1.5.sp
                )
            }
            
            // Back button (only show in management mode)
            if (isManagementMode) {
                TextButton(
                    onClick = onBack,
                    modifier = Modifier.padding(bottom = 16.dp)
                ) {
                    Text(
                        "Back to Settings",
                        color = Color.White.copy(alpha = 0.7f)
                    )
                }
            }
        }
    }
    
    // Add Profile Dialog
    if (showAddDialog) {
        AddProfileDialog(
            onDismiss = { showAddDialog = false },
            onConfirm = { newName ->
                if (newName.isNotBlank()) {
                    profiles = SettingsManager.addPersonalizedUser(context, newName)
                    SettingsManager.setUserId(context, newName)
                    SettingsManager.setPersonalizedSetupComplete(context, false, newName)
                    onProfileSelected(newName)
                }
            }
        )
    }
    
    // Delete Confirmation Dialog
    profileToDelete?.let { profile ->
        AlertDialog(
            onDismissRequest = { profileToDelete = null },
            title = { Text("Delete Profile") },
            text = { 
                Text("Are you sure you want to delete \"$profile\"? This will remove all personalized data and cannot be undone.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        SettingsManager.removePersonalizedUser(context, profile)
                        SettingsManager.setProfileImageUri(context, profile, null)
                        profiles = SettingsManager.getPersonalizedUsers(context)
                        profileToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { profileToDelete = null }) {
                    Text("Cancel")
                }
            }
        )
    }
    
    // Edit Photo Dialog
    profileToEdit?.let { profile ->
        EditPhotoDialog(
            profileName = profile,
            onDismiss = { profileToEdit = null },
            onChangePhoto = { uri ->
                SettingsManager.setProfileImageUri(context, profile, uri.toString())
                profileToEdit = null
            },
            onRemovePhoto = {
                SettingsManager.setProfileImageUri(context, profile, null)
                profileToEdit = null
            }
        )
    }
}

@Composable
private fun ProfileCard(
    name: String,
    isCurrentUser: Boolean,
    isManagementMode: Boolean = false,
    onClick: () -> Unit,
    onDelete: () -> Unit = {},
    onEditPhoto: () -> Unit = {}
) {
    val context = LocalContext.current
    val avatarColors = remember {
        listOf(
            Color(0xFFE50914), // Netflix red
            Color(0xFFFFA500), // Orange
            Color(0xFF4CAF50), // Green
            Color(0xFF2196F3), // Blue
            Color(0xFF9C27B0), // Purple
            Color(0xFFFFEB3B), // Yellow
            Color(0xFF00BCD4), // Cyan
            Color(0xFFFF5722)  // Deep Orange
        )
    }
    
    val colorIndex = remember(name) { name.hashCode().mod(avatarColors.size).let { if (it < 0) it + avatarColors.size else it } }
    val avatarColor = avatarColors[colorIndex]
    
    val profileImageUri = remember(name) { 
        SettingsManager.getProfileImageUri(context, name)
    }
    
    val imagePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            SettingsManager.setProfileImageUri(context, name, it.toString())
        }
    }
    
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .width(120.dp)
    ) {
        // Avatar
        Box(
            modifier = Modifier
                .size(120.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(avatarColor)
                .clickable { onClick() },
            contentAlignment = Alignment.Center
        ) {
            if (profileImageUri != null) {
                Image(
                    painter = rememberAsyncImagePainter(Uri.parse(profileImageUri)),
                    contentDescription = "$name profile picture",
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Crop
                )
            } else {
                Text(
                    text = name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                    style = MaterialTheme.typography.displayMedium,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 56.sp
                )
            }
            
            // Current user indicator
            if (isCurrentUser && !isManagementMode) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(6.dp)
                        .size(20.dp)
                        .clip(CircleShape)
                        .background(Color.White),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "✓",
                        color = avatarColor,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
            
            // Management mode buttons
            if (isManagementMode) {
                // Edit Photo button
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(6.dp)
                        .size(32.dp)
                        .clip(CircleShape)
                        .background(Color(0xFF2196F3).copy(alpha = 0.9f))
                        .clickable { onEditPhoto() },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Edit,
                        contentDescription = "Edit photo",
                        tint = Color.White,
                        modifier = Modifier.size(18.dp)
                    )
                }
                
                // Delete button (only if not the only profile)
                if (SettingsManager.getPersonalizedUsers(context).size > 1) {
                    Box(
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .padding(6.dp)
                            .size(32.dp)
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.error.copy(alpha = 0.9f))
                            .clickable { onDelete() },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Delete,
                            contentDescription = "Delete profile",
                            tint = Color.White,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            } else {
                // Camera icon for adding/changing image (normal mode)
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(6.dp)
                        .size(28.dp)
                        .clip(CircleShape)
                        .background(Color.Black.copy(alpha = 0.7f))
                        .clickable { imagePickerLauncher.launch("image/*") },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.CameraAlt,
                        contentDescription = "Change profile picture",
                        tint = Color.White,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
        
        Spacer(modifier = Modifier.height(12.dp))
        
        // Name
        Text(
            text = name,
            style = MaterialTheme.typography.titleSmall,
            color = Color.White.copy(alpha = 0.9f),
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center,
            maxLines = 1
        )
        
        // Setup status
        val isSetupComplete = remember(name) { 
            SettingsManager.isPersonalizedSetupComplete(context, name)
        }
        
        if (isSetupComplete) {
            Text(
                "Setup Complete",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF4CAF50),
                fontSize = 11.sp
            )
        } else {
            Text(
                "Needs Setup",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFFFF9800),
                fontSize = 11.sp
            )
        }
    }
}

@Composable
private fun AddProfileCard(
    onClick: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .width(120.dp)
            .clickable { onClick() }
    ) {
        // Add button
        Box(
            modifier = Modifier
                .size(120.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(Color.White.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Add,
                contentDescription = "Add Profile",
                tint = Color.White.copy(alpha = 0.7f),
                modifier = Modifier.size(48.dp)
            )
        }
        
        Spacer(modifier = Modifier.height(12.dp))
        
        Text(
            text = "Add Profile",
            style = MaterialTheme.typography.titleSmall,
            color = Color.White.copy(alpha = 0.7f),
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun AddProfileDialog(
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit
) {
    var profileName by remember { mutableStateOf("") }
    val canCreate = profileName.trim().length >= 3
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "Add New Profile",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Enter a name for this profile:",
                    style = MaterialTheme.typography.bodyMedium
                )
                OutlinedTextField(
                    value = profileName,
                    onValueChange = { profileName = it },
                    label = { Text("Profile Name") },
                    placeholder = { Text("e.g. John, Sarah, Desk 2") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    "Each profile will have its own personalized posture model after setup.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onConfirm(profileName.trim())
                    onDismiss()
                },
                enabled = canCreate
            ) {
                Text("Create Profile")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
        containerColor = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(16.dp)
    )
}

@Composable
private fun EditPhotoDialog(
    profileName: String,
    onDismiss: () -> Unit,
    onChangePhoto: (Uri) -> Unit,
    onRemovePhoto: () -> Unit
) {
    val context = LocalContext.current
    val currentImageUri = SettingsManager.getProfileImageUri(context, profileName)
    
    val imagePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            onChangePhoto(it)
        }
    }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                "Edit Profile Photo",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Manage photo for \"$profileName\"",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                // Show current photo if exists
                if (currentImageUri != null) {
                    Image(
                        painter = rememberAsyncImagePainter(Uri.parse(currentImageUri)),
                        contentDescription = "Current profile picture",
                        modifier = Modifier
                            .size(100.dp)
                            .clip(RoundedCornerShape(12.dp)),
                        contentScale = ContentScale.Crop
                    )
                }
                
                // Action buttons
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Button(
                        onClick = { imagePickerLauncher.launch("image/*") },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.CameraAlt,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(if (currentImageUri != null) "Change Photo" else "Add Photo")
                    }
                    
                    if (currentImageUri != null) {
                        OutlinedButton(
                            onClick = {
                                onRemovePhoto()
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Default.RemoveCircle,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Remove Photo")
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Done")
            }
        },
        containerColor = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(16.dp)
    )
}
