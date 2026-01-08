plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "io.github.iml1s"
version = "1.3.0"

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
        publishLibraryVariants("release")
    }

    jvm()

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            baseName = "txbuilder"
        }
    }

    listOf(
        watchosArm64(),
        watchosX64(),
        watchosSimulatorArm64()
    ).forEach {
        it.binaries.framework {
            baseName = "txbuilder"
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(project(":packages:crypto-pure:crypto-core"))
            implementation(project(":packages:address"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

android {
    namespace = "io.github.iml1s.tx"
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
        checkTestSources = false
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

