package io.github.iml1s.crypto

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

actual fun platformAesGcmTestSetup() {
    // Register BouncyCastle provider just in case, though standard Java crypto should handle AES-GCM
    if (Security.getProvider("BC") == null) {
        Security.addProvider(BouncyCastleProvider())
    }
}
