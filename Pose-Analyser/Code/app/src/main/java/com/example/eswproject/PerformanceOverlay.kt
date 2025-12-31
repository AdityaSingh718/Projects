package com.example.eswproject

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Performance overlay component that displays real-time metrics
 * Shows latency, FPS, and current runtime provider
 * Includes a button to cycle through runtime providers
 */
@Composable
fun PerformanceOverlay(
    metrics: PerformanceMetrics,
    onRuntimeSwitch: () -> Unit,
    modifier: Modifier = Modifier,
    isCompact: Boolean = false
) {
    Surface(
        modifier = modifier
            .shadow(
                elevation = 4.dp,
                shape = RoundedCornerShape(12.dp),
                ambientColor = Color.Black.copy(alpha = 0.2f)
            ),
        shape = RoundedCornerShape(12.dp),
        color = Color.Black.copy(alpha = 0.75f),
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Metrics display
            Column(
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                if (!isCompact) {
                    // Runtime provider
                    Text(
                        text = metrics.runtimeProvider.displayName,
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        ),
                        color = when (metrics.runtimeProvider) {
                            RuntimeProvider.CPU -> Color(0xFF60A5FA) // Blue
                            RuntimeProvider.GPU_NNAPI -> Color(0xFF34D399) // Green
                            RuntimeProvider.NPU_NNAPI -> Color(0xFFFBBF24) // Amber
                        }
                    )
                }
                
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Latency
                    MetricItem(
                        label = "Latency",
                        value = "${metrics.latencyMs}ms",
                        isCompact = isCompact
                    )
                    
                    // Separator
                    Text(
                        text = "•",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White.copy(alpha = 0.4f)
                    )
                    
                    // FPS
                    MetricItem(
                        label = "FPS",
                        value = String.format("%.1f", metrics.fps),
                        isCompact = isCompact
                    )
                    
                    if (isCompact) {
                        // Separator
                        Text(
                            text = "•",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.4f)
                        )
                        
                        // Runtime (compact)
                        Text(
                            text = when (metrics.runtimeProvider) {
                                RuntimeProvider.CPU -> "CPU"
                                RuntimeProvider.GPU_NNAPI -> "GPU"
                                RuntimeProvider.NPU_NNAPI -> "NPU"
                            },
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            ),
                            color = when (metrics.runtimeProvider) {
                                RuntimeProvider.CPU -> Color(0xFF60A5FA)
                                RuntimeProvider.GPU_NNAPI -> Color(0xFF34D399)
                                RuntimeProvider.NPU_NNAPI -> Color(0xFFFBBF24)
                            }
                        )
                    }
                }
            }
            
            // Switch runtime button - larger size
            Surface(
                modifier = Modifier
                    .size(44.dp)
                    .clickable(onClick = onRuntimeSwitch),
                shape = RoundedCornerShape(10.dp),
                color = Color.White.copy(alpha = 0.15f)
            ) {
                Box(
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.SwapHoriz,
                        contentDescription = "Switch runtime",
                        modifier = Modifier.size(26.dp),
                        tint = Color.White.copy(alpha = 0.9f)
                    )
                }
            }
        }
    }
}

@Composable
private fun MetricItem(
    label: String,
    value: String,
    isCompact: Boolean = false
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (!isCompact) {
            Text(
                text = "$label:",
                style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                color = Color.White.copy(alpha = 0.6f)
            )
        }
        Text(
            text = value,
            style = MaterialTheme.typography.labelMedium.copy(
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold
            ),
            color = Color.White
        )
    }
}

/**
 * Runtime switching dialog
 * Allows user to select between CPU, GPU, and NPU
 */
@Composable
fun RuntimeSwitchDialog(
    currentRuntime: RuntimeProvider,
    onDismiss: () -> Unit,
    onRuntimeSelected: (RuntimeProvider) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Select Runtime Provider",
                style = MaterialTheme.typography.titleMedium
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Choose the execution provider for pose detection inference:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                RuntimeProvider.values().forEach { runtime ->
                    RuntimeOption(
                        runtime = runtime,
                        isSelected = runtime == currentRuntime,
                        onClick = {
                            onRuntimeSelected(runtime)
                            onDismiss()
                        }
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@Composable
private fun RuntimeOption(
    runtime: RuntimeProvider,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(8.dp),
        color = if (isSelected) {
            MaterialTheme.colorScheme.primaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        },
        border = if (isSelected) {
            androidx.compose.foundation.BorderStroke(
                2.dp,
                MaterialTheme.colorScheme.primary
            )
        } else null
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = runtime.displayName,
                    style = MaterialTheme.typography.titleSmall.copy(
                        fontWeight = FontWeight.SemiBold
                    ),
                    color = if (isSelected) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
                Text(
                    text = when (runtime) {
                        RuntimeProvider.CPU -> "Standard CPU inference (universal)"
                        RuntimeProvider.GPU_NNAPI -> "GPU acceleration via Android NNAPI"
                        RuntimeProvider.NPU_NNAPI -> "NPU acceleration via Android NNAPI"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isSelected) {
                        MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    }
                )
            }
            
            if (isSelected) {
                Icon(
                    painter = androidx.compose.ui.res.painterResource(android.R.drawable.radiobutton_on_background),
                    contentDescription = "Selected",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
            }
        }
    }
}
