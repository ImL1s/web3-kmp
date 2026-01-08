import org.jetbrains.dokka.Platform
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.KotlinJvmTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeHostTest
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.dokka)
    `maven-publish`
}

val currentOs = org.gradle.internal.os.OperatingSystem.current()

group = "fr.acinq.bitcoin"
version = "0.30.0-SNAPSHOT"

repositories {
    google()
    mavenCentral()
}

// Robust Task Suppression to prevent CI failures
tasks.configureEach {
    val taskName = name.lowercase()
    if (taskName.contains("lint") || taskName.contains("androidtest")) {
        enabled = false
    }
}

kotlin {
    explicitApi()

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
            // See https://jakewharton.com/kotlins-jdk-release-compatibility-flag/ and https://youtrack.jetbrains.com/issue/KT-49746/
            freeCompilerArgs.add("-Xjdk-release=1.8")
        }
    }

    java {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    linuxX64()

    linuxArm64()

    macosX64()
    
    macosArm64()

    iosX64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    iosArm64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    iosSimulatorArm64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    watchosArm64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }
    watchosSimulatorArm64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }
    watchosX64 {
        compilations["main"].cinterops.create("CoreCrypto")
    }

    sourceSets {



        val commonMain by getting {
            dependencies {
                api(project(":packages:secp256k1"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
                implementation(libs.kotlinx.io.core)
                api(libs.kotlinx.serialization.json)
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
                val target = when {
                    currentOs.isLinux -> "linux"
                    currentOs.isMacOsX -> "darwin"
                    currentOs.isWindows -> "mingw"
                    else -> error("Unsupported OS $currentOs")
                }
                implementation(project(":packages:secp256k1:jni:jvm:$target"))
            }
        }

        val nativeMain by creating {
            dependsOn(commonMain)
        }
        val nativeTest by creating {
            dependsOn(commonTest)
        }

        val linuxMain by creating {
            dependsOn(nativeMain)
        }
        val linuxTest by creating {
            dependsOn(nativeTest)
        }
        val linuxX64Main by getting { dependsOn(linuxMain) }
        val linuxX64Test by getting { dependsOn(linuxTest) }
        val linuxArm64Main by getting { dependsOn(linuxMain) }
        val linuxArm64Test by getting { dependsOn(linuxTest) }

        val macosMain by creating {
            dependsOn(nativeMain)
        }
        val macosTest by creating {
            dependsOn(nativeTest)
        }
        val macosX64Main by getting { dependsOn(macosMain) }
        val macosX64Test by getting { dependsOn(macosTest) }
        val macosArm64Main by getting { dependsOn(macosMain) }
        val macosArm64Test by getting { dependsOn(macosTest) }

        val iosMain by creating {
            dependsOn(nativeMain)
        }
        val iosTest by creating {
            dependsOn(nativeTest)
        }
        val iosArm64Main by getting {
            dependsOn(iosMain)
        }
        val iosArm64Test by getting {
            dependsOn(iosTest)
        }
        val iosX64Main by getting {
            dependsOn(iosMain)
        }
        val iosX64Test by getting {
            dependsOn(iosTest)
        }
        val iosSimulatorArm64Main by getting {
            dependsOn(iosMain)
        }
        val iosSimulatorArm64Test by getting {
            dependsOn(iosTest)
        }
        
        val watchosMain by creating {
            dependsOn(nativeMain)
        }
        val watchosTest by creating {
            dependsOn(nativeTest)
        }
        val watchosArm64Main by getting {
            dependsOn(watchosMain)
        }
        val watchosArm64Test by getting {
            dependsOn(watchosTest)
        }
        val watchosSimulatorArm64Main by getting {
            dependsOn(watchosMain)
        }
        val watchosSimulatorArm64Test by getting {
            dependsOn(watchosTest)
        }
        val watchosX64Main by getting {
            dependsOn(watchosMain)
        }
        val watchosX64Test by getting {
            dependsOn(watchosTest)
        }

        all {
            languageSettings.optIn("kotlin.RequiresOptIn")
        }
    }

    // Configure all compilations of all targets:
    targets.all {
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    allWarningsAsErrors = true
                    // See https://youtrack.jetbrains.com/issue/KT-61573
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }
    }
}

configurations.forEach {
    // do not cache changing (i.e. SNAPSHOT) dependencies
    it.resolutionStrategy.cacheChangingModulesFor(0, TimeUnit.SECONDS)

    if (it.name.contains("testCompileClasspath")) {
        it.attributes.attribute(Usage.USAGE_ATTRIBUTE, objects.named(Usage::class.java, "java-runtime"))
    }
}


// Disable cross compilation
plugins.withId("org.jetbrains.kotlin.multiplatform") {
    afterEvaluate {
        val currentOs = org.gradle.internal.os.OperatingSystem.current()
        val targets = when {
            currentOs.isLinux -> listOf()
            else -> listOf("linuxX64")
        }.mapNotNull { kotlin.targets.findByName(it) as? org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget }

        configure(targets) {
            compilations.all {
                cinterops.all { tasks[interopProcessingTaskName].enabled = false }
                compileTaskProvider.configure {
                    enabled = false
                }
                tasks[processResourcesTaskName].enabled = false
            }
            binaries.all {
                linkTaskProvider.configure {
                    enabled = false
                }
            }

            mavenPublication {
                val publicationToDisable = this
                tasks.withType<AbstractPublishToMaven>().all { onlyIf { publication != publicationToDisable } }
                tasks.withType<GenerateModuleMetadata>().all { onlyIf { publication.get() != publicationToDisable } }
            }
        }
    }
}

// val dokkaOutputDir = layout.buildDirectory.dir("dokka")
//
// tasks.dokkaHtml {
//     outputDirectory.set(file(dokkaOutputDir))
//     dokkaSourceSets {
//         configureEach {
//             val platformName = when (platform.get()) {
//                 Platform.jvm -> "jvm"
//                 Platform.js -> "js"
//                 Platform.native -> "native"
//                 Platform.common -> "common"
//                 Platform.wasm -> "wasm"
//                 else -> error("unexpected platform ${platform.get()}")
//             }
//             displayName.set(platformName)
//
//             perPackageOption {
//                 matchingRegex.set(".*\\.internal.*") // will match all .internal packages and sub-packages
//                 suppress.set(true)
//             }
//         }
//     }
// }
//
// val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
//     delete(dokkaOutputDir)
// }
//
//
// val javadocJar = tasks.create<Jar>("javadocJar") {
//     archiveClassifier.set("javadoc")
//     duplicatesStrategy = DuplicatesStrategy.EXCLUDE
//     // dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
//     // from(dokkaOutputDir)
// }

publishing {
    publications.withType<MavenPublication>().configureEach {
        version = project.version.toString()
        // artifact(javadocJar)
        pom {
            name.set("Kotlin Multiplatform Bitcoin Library")
            description.set("A simple Kotlin Multiplatform library which implements most of the bitcoin protocol")
            url.set("https://github.com/ACINQ/bitcoin-kmp")
            licenses {
                license {
                    name.set("Apache License v2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0")
                }
            }
            issueManagement {
                system.set("Github")
                url.set("https://github.com/ACINQ/bitcoin-kmp/issues")
            }
            scm {
                connection.set("https://github.com/ACINQ/bitcoin-kmp.git")
                url.set("https://github.com/ACINQ/bitcoin-kmp")
            }
            developers {
                developer {
                    name.set("ACINQ")
                    email.set("hello@acinq.co")
                }
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
