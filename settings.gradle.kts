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
include(":packages:secp256k1:native")
include(":packages:secp256k1:jni")
include(":packages:secp256k1:jni:jvm")
include(":packages:secp256k1:jni:jvm:darwin")
include(":packages:secp256k1:jni:jvm:linux")
include(":packages:secp256k1:jni:jvm:mingw")
include(":packages:secp256k1:jni:jvm:all")
include(":packages:secp256k1:jni:android")
include(":packages:secp256k1:tests")
include(":packages:bitcoin")
include(":packages:address")
include(":packages:utxo")
include(":packages:tx-builder")
include(":packages:blockchain-client")
include(":packages:secure-storage")
include(":packages:solana")
include(":packages:solana:solana")
include(":packages:solana:solanapublickeys")
include(":packages:solana:base58")
include(":packages:solana:solanaeddsa")
include(":packages:solana:amount")
include(":packages:solana:readapi")
include(":packages:solana:rpc")
include(":packages:solana:signer")
include(":packages:solana:mplbubblegum")
include(":packages:solana:mpltokenmetadata")
include(":packages:caip-standards")
include(":packages:crypto-pure")
include(":packages:crypto-pure:crypto-core")
include(":packages:hardware-wallet")
include(":packages:miniscript")
include(":packages:bip21")
include(":packages:bitkey")

// Examples
include(":examples:bitcoin-wallet")

