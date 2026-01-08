plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

group = "io.github.iml1s"
version = "1.3.0"

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
        publishLibraryVariants("release", "debug")
    }

    jvm()

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            baseName = "blockchainclient"
        }
    }

    listOf(
        watchosArm64(),
        watchosX64(),
        watchosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            baseName = "blockchainclient"
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                // Local project dependencies
                implementation(project(":packages:tx-builder"))
                implementation(project(":packages:utxo"))
                
                // Ktor Client
                implementation(libs.ktor.client.core)
                implementation(libs.ktor.client.content.negotiation)
                implementation(libs.ktor.serialization.kotlinx.json)
                implementation(libs.ktor.client.logging)
                
                // Coroutines
                implementation(libs.kotlinx.coroutines.core)
                
                // Serialization
                implementation(libs.kotlinx.serialization.json)
                
                // Network (for Electrum)
                implementation(libs.ktor.network)
                implementation(libs.ktor.network.tls)
            }
        }
        
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.ktor.client.mock) // For testing without real network
        }
        
        androidMain.dependencies {
            implementation(libs.ktor.client.okhttp)
        }
        
        jvmMain.dependencies {
            implementation(libs.ktor.client.okhttp)
        }
        
        val iosMain by creating { dependsOn(commonMain) }
        val iosX64Main by getting { dependsOn(iosMain) }
        val iosArm64Main by getting { dependsOn(iosMain) }
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }

        val watchosMain by creating { dependsOn(commonMain) }
        val watchosArm64Main by getting { dependsOn(watchosMain) }
        val watchosX64Main by getting { dependsOn(watchosMain) }
        val watchosSimulatorArm64Main by getting { dependsOn(watchosMain) }

        iosMain.dependencies {
            implementation(libs.ktor.client.darwin)
        }
    }
}

android {
    namespace = "io.github.iml1s.client"
    compileSdk = 35
    defaultConfig {
        minSdk = 26
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint {
        abortOnError = false
        checkReleaseBuilds = false
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
