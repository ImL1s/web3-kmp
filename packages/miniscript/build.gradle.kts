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
                implementation("io.github.iml1s:kotlin-crypto-pure:1.0.0") // Core Scripts/Transactons
                implementation("io.github.iml1s:kotlin-address:1.0.0") // Bech32, Base58 checks
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
    compileSdk = 34
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}
