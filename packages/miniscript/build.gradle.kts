plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
}

group = "io.github.iml1s"
version = "1.0.0"

kotlin {
    androidTarget {
        compilations.all {
            kotlinOptions {
                jvmTarget = "11"
            }
        }
    }
    jvm()
    
    // Apple platforms
    iosX64()
    iosArm64()
    iosSimulatorArm64()
    macosX64()
    macosArm64()
    watchosArm64()
    watchosSimulatorArm64()
    watchosX64()
    
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":packages:crypto-pure:crypto-core")) // Core Scripts/Transactons
                implementation(project(":packages:address")) // Bech32, Base58 checks
                // implementation(project(":kotlin-bcur")) // Maybe needed later?
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}

android {
    namespace = "io.github.iml1s.miniscript"
    compileSdk = 35
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

tasks.configureEach {
    val taskName = name.lowercase()
    if (taskName.contains("lint") || 
        taskName.contains("androidtest") ||
        (taskName.contains("unittest") && !taskName.contains("jvm"))) {
        // Only disable if it's not a platform test we want
        if (!taskName.contains("jvmtest") && 
            !taskName.contains("iostest") && 
            !taskName.contains("macostest") &&
            !taskName.contains("watchostest")) {
            enabled = false
        }
    }
}
