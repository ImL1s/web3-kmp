plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    sourceSets {
        commonMain.dependencies {
            // Core wallet dependencies
            implementation(project(":packages:utxo"))
            implementation(project(":packages:blockchain-client"))
            implementation(project(":packages:bip21"))
            implementation(libs.kotlinx.coroutines.core)
        }
        jvmMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.ktor.client.core)
            implementation(libs.ktor.client.cio)
            implementation(libs.ktor.client.content.negotiation)
            implementation(libs.ktor.serialization.kotlinx.json)
            implementation("org.slf4j:slf4j-simple:2.0.9") // For Ktor logging
        }
    }
}

// Custom run task for JVM target
tasks.register<JavaExec>("jvmRun") {
    group = "application"
    description = "Runs the JVM demo application"
    
    val jvmCompilations = kotlin.targets.getByName("jvm").compilations
    val mainCompilation = jvmCompilations.getByName("main")
    
    classpath = (mainCompilation.runtimeDependencyFiles ?: files()) + mainCompilation.output.allOutputs
    
    mainClass.set("io.github.iml1s.wallet.MainKt")
    
    // Optional: Pass arguments if needed
    // args = listOf("arg1", "arg2")
}
