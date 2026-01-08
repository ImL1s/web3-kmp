# Install
The library is currently deployed to Maven Central's snapshot repository under the group ID `org.kotlinbitcointools` and the artifact ID `bip21`. You can import it in your project as you would any other Maven dependency provided you have the snapshot Maven repository configured as a dependency source:

```kotlin title="settings.gradle.kts"
dependencyResolutionManagement {
    repositories {
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        // mavenCentral()
    }
}
```

```kotlin title="build.gradle.kts"
implementation("org.kotlinbitcointools:bip21:0.1.0-SNAPSHOT")
```

## Build and deploy locally
To build the library locally and deploy to your local Maven repository, run the following command:
```shell
./gradlew publishToMavenLocal
```

The library will be available in your local Maven repository (typically at `~/.m2/repository/` for macOS and Linux systems) under the group ID `org.kotlinbitcointools` and the artifact ID `bip21`. You can import it in your project as you would any other Maven dependency provided you have your local Maven repository (`mavenLocal()`) configured as a dependency source:
```kotlin title="settings.gradle.kts"
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        mavenLocal()
    }
}
```

```kotlin title="build.gradle.kts"
implementation("org.kotlinbitcointools:bip21:0.1.0-SNAPSHOT")
```

[BIP-0021]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
[issues]: https://github.com/kotlin-bitcoin-tools/bip21/issues
