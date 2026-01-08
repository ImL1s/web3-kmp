plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

kotlin {
    jvm {
        mainRun {
            mainClass.set("io.github.iml1s.crypto.demo.cli.MainKt")
        }
    }
    
    // Native targets for CLI
    macosArm64 {
        binaries {
            executable {
                entryPoint = "io.github.iml1s.crypto.demo.cli.main"
                baseName = "crypto-cli"
            }
        }
    }
    macosX64 {
        binaries {
            executable {
                entryPoint = "io.github.iml1s.crypto.demo.cli.main"
                baseName = "crypto-cli"
            }
        }
    }
    // Linux and Windows native targets disabled - crypto-core doesn't support them yet
//    linuxX64 {
//        binaries {
//            executable {
//                entryPoint = "io.github.iml1s.crypto.demo.cli.main"
//                baseName = "crypto-cli"
//            }
//        }
//    }
//    mingwX64 {
//        binaries {
//            executable {
//                entryPoint = "io.github.iml1s.crypto.demo.cli.main"
//                baseName = "crypto-cli"
//            }
//        }
//    }

    sourceSets {
        commonMain.dependencies {
            implementation(project(":crypto-core"))
            implementation(libs.clikt)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        jvmTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
