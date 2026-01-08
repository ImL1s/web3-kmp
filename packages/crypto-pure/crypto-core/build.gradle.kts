plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    `maven-publish`
}

// Library version and metadata
group = "io.github.iml1s"
version = "1.3.0"

kotlin {
    jvm {
        compilerOptions {
            freeCompilerArgs.add("-Xexpect-actual-classes")
        }
    }
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
            freeCompilerArgs.add("-opt-in=kotlin.ExperimentalStdlibApi")
            freeCompilerArgs.add("-Xexpect-actual-classes")
        }
        // Enable publishing for Android target
        publishLibraryVariants("release", "debug")
    }
    listOf(
        iosArm64(),
        iosSimulatorArm64(),
        iosX64(),
        watchosArm64(),
        watchosSimulatorArm64(),
        watchosX64()
    ).forEach { target ->
        target.compilations.getByName("main") {
            cinterops {
                val CommonCrypto by creating {
                    definitionFile.set(project.file("src/nativeInterop/cinterop/CommonCrypto.def"))
                    packageName = "commonCrypto"
                    includeDirs("src/nativeInterop/cinterop")
                }
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlin:kotlin-stdlib")
                api("org.kotlincrypto.hash:sha3:0.5.3")
                api("org.kotlincrypto.hash:sha2:0.5.3")
                api("com.ionspin.kotlin:bignum:0.3.9")
                api("io.github.andreypfau:curve25519-kotlin:0.0.8")
            }
        }

        val commonTest by getting {
            dependencies {
                implementation("org.jetbrains.kotlin:kotlin-test")
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.0")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.4.1")
            }
        }

        val androidMain by getting {
            dependencies {
                implementation("androidx.core:core-ktx:1.13.1")
                api("fr.acinq.secp256k1:secp256k1-kmp:0.19.0")
                api("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.19.0")
                api("org.bouncycastle:bcprov-jdk18on:1.78.1")
            }
        }

        val androidUnitTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                implementation("junit:junit:4.13.2")
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.19.0")
            }
        }

        // Shared Native Main source set (iOS & watchOS)
        val nativeMain by creating {
            dependsOn(commonMain)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
            }
        }

        // iosMain will now inherit from nativeMain
        val iosMain by creating {
            dependsOn(nativeMain)
            dependencies {
                api("fr.acinq.secp256k1:secp256k1-kmp:0.19.0")
            }
        }

        // Link iOS targets to iosMain
        val iosArm64Main by getting { dependsOn(iosMain) }
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }
        val iosX64Main by getting { dependsOn(iosMain) }

        // watchosMain will now inherit from nativeMain
        val watchosMain by creating {
            dependsOn(nativeMain)
        }

        // Link watchOS targets to watchosMain
        val watchosArm64Main by getting { dependsOn(watchosMain) }
        val watchosSimulatorArm64Main by getting { dependsOn(watchosMain) }
        val watchosX64Main by getting { dependsOn(watchosMain) }

        // Shared Native Test source set (iOS & watchOS)
        val nativeTest by creating {
            dependsOn(commonTest)
        }

        val iosArm64Test by getting { dependsOn(nativeTest) }
        val iosSimulatorArm64Test by getting { dependsOn(nativeTest) }
        val iosX64Test by getting { dependsOn(nativeTest) }

        val watchosArm64Test by getting { dependsOn(nativeTest) }
        val watchosSimulatorArm64Test by getting { dependsOn(nativeTest) }
        val watchosX64Test by getting { dependsOn(nativeTest) }

        val jvmMain by getting {
            dependsOn(commonMain)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
                api("org.bouncycastle:bcprov-jdk18on:1.78.1")
            }
        }

        val jvmTest by getting {
            dependsOn(commonTest)
            dependencies {
                implementation(kotlin("test"))
                implementation(kotlin("test-junit"))
            }
        }
    }
}

android {
    namespace = "io.github.iml1s.crypto"
    compileSdk = 35
    defaultConfig {
        minSdk = 26
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = false
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

// Maven publishing configuration for JitPack
afterEvaluate {
    publishing {
        publications {
                // Configure KMP publications
                withType<MavenPublication>().configureEach {
                    pom {
                    name.set("Kotlin Crypto Pure")
                    description.set("Pure Kotlin cryptographic library for multiplatform (Android, iOS, watchOS)")
                    url.set("https://github.com/iml1s/kotlin-crypto-pure")

                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://opensource.org/licenses/MIT")
                        }
                    }

                    developers {
                        developer {
                            id.set("iml1s")
                            name.set("iml1s")
                        }
                    }

                    scm {
                        connection.set("scm:git:git://github.com/iml1s/kotlin-crypto-pure.git")
                        developerConnection.set("scm:git:ssh://github.com:iml1s/kotlin-crypto-pure.git")
                        url.set("https://github.com/iml1s/kotlin-crypto-pure/tree/main")
                    }
                }
            }
        }
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

