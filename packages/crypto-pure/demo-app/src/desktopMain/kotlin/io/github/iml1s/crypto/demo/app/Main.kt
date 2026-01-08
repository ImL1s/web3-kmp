package io.github.iml1s.crypto.demo.app

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication,
        title = "Kotlin Crypto Pure Demo"
    ) {
        App()
    }
}
