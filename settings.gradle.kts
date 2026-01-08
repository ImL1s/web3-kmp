rootProject.name = "web3-kmp"

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}


include(":packages:secp256k1")
include(":packages:bitcoin")
include(":packages:address")
include(":packages:utxo")
include(":packages:tx-builder")
include(":packages:blockchain-client")
include(":packages:secure-storage")
include(":packages:solana")
include(":packages:caip-standards")
include(":packages:crypto-pure")
include(":packages:hardware-wallet")
include(":packages:miniscript")
include(":packages:bip21")
include(":packages:bitkey")

