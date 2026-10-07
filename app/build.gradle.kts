import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val targetAbis = (project.findProperty("targetAbi") as String?)?.split(',')?.map(String::trim)?.filter(String::isNotEmpty) ?: listOf("arm64-v8a", "armeabi-v7a", "x86_64")
val releaseKeystore = (project.findProperty("aetheryKeystore") as String?)?.takeIf { rootProject.file(it).let { f -> f.isFile && f.length() > 0 } }

android {
    namespace = "com.msnguard.vpn"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "26.3.11579264"

    // Keep Kotlin on the JDK already installed by GitHub Actions.
    kotlinOptions {
        jvmTarget = "17"
    }

    defaultConfig {
        applicationId = "com.parvaz.vpn"
        minSdk = 26
        targetSdk = 36
        versionCode = 275
        versionName = "2.3.7"
    }

    splits {
        abi {
            isEnable = true
            reset()
            include(*targetAbis.toTypedArray())
            isUniversalApk = true
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging { jniLibs { useLegacyPackaging = true } }

    if (releaseKeystore != null) {
        val envProps = Properties().apply {
            val envFile = rootProject.file("keystore.env")
            if (envFile.exists()) envFile.inputStream().use { load(it) }
        }
        signingConfigs {
            create("release") {
                storeFile = rootProject.file(releaseKeystore)
                storePassword = System.getenv("AETHERY_KEYSTORE_PASSWORD") ?: envProps.getProperty("storePassword")
                keyAlias = System.getenv("AETHERY_KEY_ALIAS") ?: envProps.getProperty("keyAlias")
                keyPassword = System.getenv("AETHERY_KEY_PASSWORD") ?: envProps.getProperty("keyPassword")
                enableV1Signing = true
                enableV2Signing = true
            }
        }
        buildTypes.named("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
            isShrinkResources = false
            isDebuggable = false
        }
    } else {
        buildTypes.named("release") {
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
            isShrinkResources = false
            isDebuggable = false
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.core:core-splashscreen:1.0.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
}

val yektaRebrand = tasks.register<Exec>("yektaRebrand") {
    group = "build"
    description = "Applies Yekta VPN branding"
    onlyIf { !org.gradle.internal.os.OperatingSystem.current().isWindows }
    commandLine("bash", rootProject.file("tools/rebrand.sh").absolutePath)
}
tasks.named("preBuild").configure { dependsOn(yektaRebrand) }

targetAbis.forEach { abi ->
    val taskName = "buildRustCore${abi.split('-').joinToString("") { it.replaceFirstChar(Char::uppercase) }}"
    tasks.register<Exec>(taskName) {
        group = "build"
        description = "Builds Aether for Android $abi"
        val buildScript = if (org.gradle.internal.os.OperatingSystem.current().isWindows) rootProject.file("core/build-android.ps1") else rootProject.file("core/build-android.sh")
        if (org.gradle.internal.os.OperatingSystem.current().isWindows) commandLine("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", buildScript.absolutePath, "-Abi", abi) else commandLine("bash", buildScript.absolutePath, "--abi", abi)
        environment("ANDROID_HOME", android.sdkDirectory.absolutePath)
        environment("ANDROID_SDK_ROOT", android.sdkDirectory.absolutePath)
        environment("ANDROID_NDK_HOME", "${android.sdkDirectory.absolutePath}/ndk/26.3.11579264")
        environment("ANDROID_NDK_ROOT", "${android.sdkDirectory.absolutePath}/ndk/26.3.11579264")
        inputs.dir(rootProject.file("core/aether/src"))
        inputs.file(rootProject.file("core/aether/Cargo.toml"))
        inputs.dir(rootProject.file("core/quiche"))
        inputs.file(buildScript)
        outputs.file(file("src/main/jniLibs/$abi/libaether.so"))
    }
    tasks.named("preBuild").configure { dependsOn(taskName) }
}
