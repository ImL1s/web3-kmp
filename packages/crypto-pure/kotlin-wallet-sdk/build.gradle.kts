plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    jvm()
    
    // Future: ios(), android(), js()
    
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":packages:crypto-pure:crypto-core"))
                implementation(project(":packages:blockchain-client"))
                implementation(project(":packages:tx-builder"))
                implementation(project(":packages:utxo"))
                implementation(project(":packages:address"))
                implementation(project(":packages:solana:solana"))
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
