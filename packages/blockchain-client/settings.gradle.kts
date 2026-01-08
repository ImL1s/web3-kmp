pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "kotlin-blockchain-client"

fun includeBuildIfExists(path: String) {
    if (file(path).exists()) {
        includeBuild(path)
    }
}

includeBuildIfExists("../kotlin-crypto-pure")
includeBuildIfExists("../kotlin-tx-builder")
includeBuildIfExists("../kotlin-utxo")
includeBuildIfExists("../kotlin-address")
includeBuildIfExists("../kotlin-solana")
