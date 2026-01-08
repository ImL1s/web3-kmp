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

rootProject.name = "kotlin-miniscript"

val cryptoPure = file("../kotlin-crypto-pure")
if (cryptoPure.exists()) {
    includeBuild(cryptoPure)
}

val address = file("../kotlin-address")
if (address.exists()) {
    includeBuild(address)
}
