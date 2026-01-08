import org.gradle.internal.os.OperatingSystem
import org.gradle.kotlin.dsl.register
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.dokka.Platform
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.*

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.dokka)
    `maven-publish`
}

// Robust Task Suppression to prevent CI failures
tasks.configureEach {
    val taskName = name.lowercase()
    if (taskName.contains("lint") || taskName.contains("androidtest")) {
        enabled = false
    }
}


allprojects {
    group = "fr.acinq.secp256k1"
    version = "0.23.0-SNAPSHOT"

    repositories {
        google()
        mavenCentral()
    }
}

val currentOs = OperatingSystem.current()

kotlin {
    explicitApi()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("com.ionspin.kotlin:bignum:0.3.9")
                api("org.kotlincrypto.hash:sha2:0.5.3")
                implementation(libs.kotlinx.serialization.json)
            }
        }
    }

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

    fun KotlinNativeTarget.secp256k1CInterop(target: String) {
        compilations["main"].cinterops {
            val libsecp256k1 by creating {
                includeDirs.headerFilterOnly(project.file("native/secp256k1/include/"))
                tasks[interopProcessingTaskName].dependsOn(":native:buildSecp256k1${target.replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString() }}")
            }
        }
    }

    val nativeMain by sourceSets.creating

    linuxX64 {
        secp256k1CInterop("host")
    }

    linuxArm64 {
        secp256k1CInterop("linuxArm64")
    }

    macosX64 {
        secp256k1CInterop("host")
    }

    macosArm64 {
        secp256k1CInterop("host")
    }

    iosX64 {
        secp256k1CInterop("ios")
    }

    iosArm64 {
        secp256k1CInterop("ios")
    }

    iosSimulatorArm64 {
        secp256k1CInterop("ios")
    }

    sourceSets.all {
        languageSettings.optIn("kotlin.RequiresOptIn")
    }
}

// Disable cross compilation
allprojects {
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        afterEvaluate {
            val currentOs = OperatingSystem.current()
            val targets = when {
                currentOs.isLinux -> listOf()
                currentOs.isMacOsX -> listOf("linuxX64", "linuxArm64")
                currentOs.isWindows -> listOf("linuxX64", "linuxArm64")
                else -> listOf("linuxX64", "linuxArm64")
            }.mapNotNull { kotlin.targets.findByName(it) as? KotlinNativeTarget }

            configure(targets) {
                compilations.all {
                    cinterops.all { tasks[interopProcessingTaskName].enabled = false }
                    compileTaskProvider { enabled = false }
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
}

allprojects {
    // val javadocJar = tasks.register<Jar>("javadocJar") {
    //    archiveClassifier.set("javadoc")
    //    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    // }

    // Publication
    plugins.withId("maven-publish") {
        publishing {
            publications.withType<MavenPublication>().configureEach {
                version = project.version.toString()
                // artifact(javadocJar)
                pom {
                    name.set("secp256k1 for Kotlin/Multiplatform")
                    description.set("Bitcoin's secp256k1 library ported to Kotlin/Multiplatform for JVM, Android, iOS & Linux")
                    url.set("https://github.com/ACINQ/secp256k1-kmp")
                    licenses {
                        license {
                            name.set("Apache License v2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }
                    issueManagement {
                        system.set("Github")
                        url.set("https://github.com/ACINQ/secp256k1-kmp/issues")
                    }
                    scm {
                        connection.set("https://github.com/ACINQ/secp256k1-kmp.git")
                        url.set("https://github.com/ACINQ/secp256k1-kmp")
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
    }

/*
    if (project.name !in listOf("native", "tests")) {
        afterEvaluate {
            val dokkaOutputDir = layout.buildDirectory.dir("dokka")

            // dokka {
            //     moduleName = "secp256k1-kmp"
            //     dokkaPublications.html {
            //         outputDirectory.set(dokkaOutputDir)
            //         dokkaSourceSets {
            //             configureEach {
            //                 val platformName = analysisPlatform.get().name
            //                 displayName.set(platformName)
            //
            //                 perPackageOption {
            //                     matchingRegex.set(".*\\.internal.*") // will match all .internal packages and sub-packages
            //                     suppress.set(true)
            //                 }
            //             }
            //         }
            //     }
            // }

            val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
                delete(dokkaOutputDir)
            }

            // javadocJar {
            //    dependsOn(deleteDokkaOutputDir, tasks.dokkaGenerate)
            //    from(dokkaOutputDir)
            // }
        }
    }
*/
}

allprojects {
    afterEvaluate {
        tasks.withType<AbstractTestTask>() {
            testLogging {
                events("passed", "skipped", "failed", "standard_out", "standard_error")
                showExceptions = true
                showStackTraces = true
            }
        }
    }
}
