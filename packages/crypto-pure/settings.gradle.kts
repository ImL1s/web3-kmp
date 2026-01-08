pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()

    }
}

rootProject.name = "kotlin-crypto-pure"

include(":crypto-core")
include(":demo-cli")
include(":demo-app")
include(":kotlin-wallet-sdk")

// Composite Builds for Unified SDK (Standardized at version 1.3.0)
fun includeBuildIfExists(path: String) {
    val buildFile = file(path)
    if (buildFile.exists()) {
        println("ANTIGRAVITY: Including build from ${buildFile.absolutePath}")
        includeBuild(path)
    } else {
        println("ANTIGRAVITY: Build path ${buildFile.absolutePath} does not exist!")
    }
}

includeBuildIfExists("../kotlin-blockchain-client")
includeBuildIfExists("../kotlin-tx-builder")
includeBuildIfExists("../kotlin-utxo")
includeBuildIfExists("../kotlin-address")
includeBuildIfExists("../kotlin-solana")

