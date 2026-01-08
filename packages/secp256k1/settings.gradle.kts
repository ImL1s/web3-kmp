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
val cryptoPath = listOf("../kotlin-crypto-pure", "./kotlin-crypto-pure")
    .map { file(it) }
    .firstOrNull { it.exists() }

if (cryptoPath != null) {
    includeBuild(cryptoPath)
}

rootProject.name = "secp256k1-kmp"

// We use a property defined in `local.properties` to know whether we should build the android application or not.
// For example, iOS developers may want to skip that most of the time.
val skipAndroid = File("$rootDir/local.properties").takeIf { it.exists() }
    ?.inputStream()?.use { java.util.Properties().apply { load(it) } }
    ?.run { getProperty("skip.android", "false")?.toBoolean() }
    ?: false

// Use system properties to inject the property in other gradle build files.
System.setProperty("includeAndroid", (!skipAndroid).toString())

include(
    ":native",
    ":jni",
    ":jni:jvm",
    ":jni:jvm:darwin",
    ":jni:jvm:linux",
    ":jni:jvm:mingw",
    ":jni:jvm:all",
    ":tests"
)

if (!skipAndroid) {
    print("building android library")
    include(":jni:android")
} else {
    print("skipping android build")
}
