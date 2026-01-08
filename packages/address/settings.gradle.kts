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

rootProject.name = "kotlin-address"

val cryptoPure = file("../kotlin-crypto-pure")
if (cryptoPure.exists()) {
    includeBuild(cryptoPure)
}
