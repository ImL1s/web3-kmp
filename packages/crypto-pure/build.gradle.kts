plugins {
    // Declare plugins without applying in root
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.compose) apply false
    alias(libs.plugins.compose.compiler) apply false
}

// Root project configuration
group = "io.github.iml1s"
version = "1.3.0"
