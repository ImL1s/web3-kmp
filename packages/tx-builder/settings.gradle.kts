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

rootProject.name = "kotlin-tx-builder"

val cryptoPure = file("../kotlin-crypto-pure")
if (cryptoPure.exists()) {
    includeBuild(cryptoPure)
}

val address = file("../kotlin-address")
if (address.exists()) {
    includeBuild(address)
}
