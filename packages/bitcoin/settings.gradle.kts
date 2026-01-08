
rootProject.name = "bitcoin-kmp"

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
    }

    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith("org.jetbrains.kotlin")) {
                useVersion("2.1.0")
            }
            if (requested.id.id == "com.android.library" || requested.id.id == "com.android.application") {
                useModule("com.android.tools.build:gradle:8.2.0")
            }
        }
    }
}

val secpPath = listOf("../kotlin-secp256k1-kmp", "../secp256k1-kmp", "./kotlin-secp256k1-kmp")
    .map { file(it) }
    .firstOrNull { it.exists() }

if (secpPath != null) {
    includeBuild(secpPath) {
        dependencySubstitution {
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp")).using(project(":"))
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-common")).using(project(":jni"))
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-extract")).using(project(":jni:jvm"))
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-linux")).using(project(":jni:jvm:linux"))
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-darwin")).using(project(":jni:jvm:darwin"))
            substitute(module("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-mingw")).using(project(":jni:jvm:mingw"))
        }
    }
}

val cryptoPath = listOf("../kotlin-crypto-pure", "./kotlin-crypto-pure")
    .map { file(it) }
    .firstOrNull { it.exists() }

if (cryptoPath != null) {
    println("ANTIGRAVITY: Including crypto-pure from $cryptoPath")
    includeBuild(cryptoPath)
}
