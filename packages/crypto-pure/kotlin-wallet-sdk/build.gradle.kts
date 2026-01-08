plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    jvm()
    
    // Future: ios(), android(), js()
    
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":crypto-core"))
                implementation("io.github.iml1s:kotlin-blockchain-client:1.3.0")
                implementation("io.github.iml1s:kotlin-tx-builder:1.3.0")
                implementation("io.github.iml1s:kotlin-utxo:1.3.0")
                implementation("io.github.iml1s:kotlin-address:1.3.0")
                implementation("io.github.iml1s:solana:1.3.0")
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.ktor.client.core)
                implementation(libs.ktor.client.content.negotiation)
                implementation(libs.ktor.serialization.kotlinx.json)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(libs.ktor.client.okhttp)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
