group = "io.github.iml1s"
version = "1.3.0"

// import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    // alias(libs.plugins.maven.publish)
    // alias(libs.plugins.kmp.framework.bundler)
}

@OptIn(org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi::class)
kotlin {
    applyDefaultHierarchyTemplate()

    androidTarget().apply {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        }
    }
    jvm()

    // val xcf = XCFramework()
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
        macosX64(),
        macosArm64(),
        watchosArm64(),
        watchosSimulatorArm64(),
        watchosX64()
    ).forEach {
        it.binaries.framework {
            baseName = "solana"
            // xcf.add(this)

            export(project(":packages:solana:amount"))
            export(project(":packages:solana:base58"))
            export(project(":packages:solana:readapi"))
            export(project(":packages:solana:amount"))
            export(project(":packages:solana:rpc"))
            export(project(":packages:solana:signer"))
            export(project(":packages:solana:solanaeddsa"))
            export(project(":packages:solana:solanapublickeys"))
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(project(":packages:solana:amount"))
                api(project(":packages:solana:base58"))
                api(project(":packages:solana:readapi"))
                api(project(":packages:solana:rpc"))
                api(project(":packages:solana:signer"))
                api(project(":packages:solana:solanaeddsa"))
                api(project(":packages:solana:solanapublickeys"))
                implementation(libs.buffer)
                implementation(libs.kborsh)
                implementation(libs.kotlinx.serialization.json)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.web3solana)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        val jvmMain by getting
        val jvmTest by getting
    }
}

android { namespace = "foundation.metaplex.solana"
    compileSdk = 33
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

/* mavenPublishing {
    coordinates(group as String, "solana", version as String)
} */

/* frameworkBundlerConfig {
    frameworkName.set("solana")
    outputPath.set("$rootDir/XCFrameworkOutputs")
    versionName.set(version as String)
    frameworkType = com.prof18.kmpframeworkbundler.data.FrameworkType.XC_FRAMEWORK
} */




