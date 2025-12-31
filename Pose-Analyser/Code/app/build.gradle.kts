import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    id("com.google.gms.google-services")
    id("com.chaquo.python")
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        file.inputStream().use { load(it) }
    }
}

val chaquopyDefaultPythonVersion = "3.8"

val chaquopyPythonVersion = (
    project.findProperty("chaquopyPythonVersion") as String?
        ?: localProperties.getProperty("chaquopy.python.version")
)?.ifBlank { null } ?: chaquopyDefaultPythonVersion

val chaquopyPythonPath = (
    project.findProperty("chaquopyPythonPath") as String?
        ?: localProperties.getProperty("chaquopy.python.path")
        ?: System.getenv("CHAQUOPY_PYTHON_PATH")
)?.ifBlank { null }

if (chaquopyPythonVersion != chaquopyDefaultPythonVersion) {
    logger.warn(
        "[Chaquopy] Overriding python version to $chaquopyPythonVersion. " +
            "Only $chaquopyDefaultPythonVersion is guaranteed to have prebuilt numpy/scikit-learn wheels."
    )
}

android {
    namespace = "com.example.eswproject"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.eswproject"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        // Native library configuration for 16KB page size compatibility
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")  // Remove x86/x86_64 to avoid alignment issues
        }
    }
    
    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
    }
    
    // Configure for 16KB page size compatibility
    packaging {
        jniLibs {
            useLegacyPackaging = false  // Use modern packaging
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    
    // Note: Using ndk abiFilters above instead of splits to avoid conflicts
}

// Chaquopy Python configuration
chaquopy {
    defaultConfig {
        version = chaquopyPythonVersion
        chaquopyPythonPath?.takeIf { it.isNotBlank() }?.let { buildPython(it) }
        if (chaquopyPythonPath.isNullOrBlank()) {
            logger.lifecycle(
                "[Chaquopy] Using default Python $chaquopyPythonVersion. " +
                    "Set chaquopy.python.path (local.properties or Gradle property) to point at a matching interpreter if you need deterministic .pyc compilation."
            )
        }
        pip {
            // Core dependencies for personalized posture detection
            // Note: LightGBM removed due to native library compatibility issues on Android
            // Using scikit-learn's GradientBoostingClassifier instead (pure Python, no native deps)
            install("numpy")
            install("pandas")
            install("scikit-learn")
            install("joblib")
        }
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.compose.material:material-icons-extended:1.7.8")
    
    // Coil for image loading
    implementation("io.coil-kt:coil-compose:2.5.0")
    
    // Camera dependencies
    implementation("androidx.camera:camera-core:1.5.0")
    implementation("androidx.camera:camera-camera2:1.5.0")
    implementation("androidx.camera:camera-lifecycle:1.5.0")
    implementation("androidx.camera:camera-view:1.5.0")
    implementation("androidx.camera:camera-extensions:1.5.0")
    
    // ONNX Runtime for YOLOv11n-pose model inference with NNAPI support
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.17.0")
    // ONNX Runtime extensions for NNAPI acceleration (GPU/NPU)
    implementation("com.microsoft.onnxruntime:onnxruntime-extensions-android:0.9.0")
    
    // TensorFlow Lite for universal compatibility (16KB page size compatible)
    implementation("org.tensorflow:tensorflow-lite:2.16.1")
    implementation("org.tensorflow:tensorflow-lite-gpu:2.16.1") 
    implementation("org.tensorflow:tensorflow-lite-support:0.4.4")
    
    // Coroutines for asynchronous processing
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.7.3")
    
    // Image processing utilities
    implementation("androidx.exifinterface:exifinterface:1.3.7")
    
    // Firebase dependencies
    implementation(platform("com.google.firebase:firebase-bom:33.4.0"))
    implementation("com.google.firebase:firebase-database-ktx")
    implementation("com.google.firebase:firebase-analytics-ktx")
    implementation("com.google.firebase:firebase-auth-ktx")
    
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}