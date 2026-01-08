import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.KotlinJvmTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeHostTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
}

repositories {
    mavenCentral()
}

val includeAndroid = System.getProperty("includeAndroid")?.toBoolean() ?: true

kotlin {
    explicitApi()

    if (includeAndroid) {
        androidTarget {
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_1_8)
            }
            @OptIn(ExperimentalKotlinGradlePluginApi::class)
            instrumentedTestVariant {
                // This makes instrumented tests depend on commonTest source
                sourceSetTree.set(KotlinSourceSetTree.test)
            }
        }
    }

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
            // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
            freeCompilerArgs.add("-Xjdk-release=1.8")
        }
        compilations["main"].dependencies {
            implementation(project(":packages:secp256k1:jni:jvm:all"))
        }
        compilations["test"].dependencies {
            implementation(kotlin("test-junit"))
        }
    }

    applyDefaultHierarchyTemplate()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":packages:secp256k1"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
                implementation(libs.kotlinx.io.core)
                api(libs.kotlinx.serialization.json)
                implementation("org.kotlincrypto.hash:sha2:0.5.3")
                implementation("org.kotlincrypto.hash:sha2:0.5.3")
            }
        }
        if (includeAndroid) {
            val androidMain by getting {
                dependencies {
                    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.4")
                }
            }
            val androidInstrumentedTest by getting {
                dependencies {
                    implementation(kotlin("test-junit"))
                    implementation("junit:junit:4.13.2")
                    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
                    implementation(project(":packages:secp256k1"))
                }
            }
        }
    }
    linuxX64()
    macosX64()
    macosArm64()
    iosX64()
    iosArm64()
    iosSimulatorArm64()
}

if (includeAndroid) {
    extensions.configure<com.android.build.gradle.LibraryExtension>("android") {
        namespace = "fr.acinq.secp256k1.tests"

        defaultConfig {
            compileSdk = 35
            minSdk = 21
            testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_1_8
            targetCompatibility = JavaVersion.VERSION_1_8
        }

        sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")

        afterEvaluate {
            tasks.withType<com.android.build.gradle.tasks.factory.AndroidUnitTest>().all {
                enabled = false
            }
        }
    }
}

afterEvaluate {
    tasks.withType<AbstractTestTask> {
        testLogging {
            events("passed", "skipped", "failed", "standard_out", "standard_error")
            showExceptions = true
            showStackTraces = true
        }
    }

    tasks.withType<KotlinJvmTest> {
        environment("TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }

    tasks.withType<KotlinNativeHostTest> {
        environment("TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }

    tasks.withType<KotlinNativeSimulatorTest> {
        environment("SIMCTL_CHILD_TEST_RESOURCES_PATH", projectDir.resolve("src/commonTest/resources"))
    }
}
