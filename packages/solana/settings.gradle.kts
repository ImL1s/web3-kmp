pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()

    }
}

rootProject.name = "kotlin-solana"

fun includeBuildIfExists(path: String) {
    if (file(path).exists()) {
        println("ANTIGRAVITY: Including build from $path")
        includeBuild(path)
    } else {
        println("ANTIGRAVITY: Build path $path does not exist!")
    }
}

includeBuildIfExists("../kotlin-crypto-pure")
includeBuildIfExists("../kotlin-address")

include(":solana")
include(":solanapublickeys")
include(":base58")
include(":solanaeddsa")
include(":amount")
include(":readapi")
include(":rpc")
include(":signer")
include(":mplbubblegum")
include(":mpltokenmetadata")

