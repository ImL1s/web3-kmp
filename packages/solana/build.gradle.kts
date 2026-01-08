import org.jetbrains.kotlin.gradle.plugin.extraProperties

group = "io.github.iml1s"
version = "1.3.0"

// buildscript {
//     dependencies {
//         classpath(libs.gradle)
//     }
// }
plugins {
    alias(libs.plugins.android.library).apply(false)
    alias(libs.plugins.kotlin.multiplatform).apply(false)
    // // alias(libs.plugins.maven.publish).apply(false)
    // // alias(libs.plugins.kmp.framework.bundler).apply(false)
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}

subprojects.forEach { project ->
    project.tasks.configureEach {
        val taskName = name.lowercase()
        if (taskName.contains("lint") || 
            taskName.contains("androidtest") ||
            (taskName.contains("unittest") && !taskName.contains("jvm"))) {
            // Only disable if it's not a platform test we want
            if (!taskName.contains("jvmtest") && 
                !taskName.contains("iostest") && 
                !taskName.contains("macostest") &&
                !taskName.contains("watchostest")) {
                enabled = false
            }
        }
    }
    project.afterEvaluate {
        project.tasks.filterIsInstance<Test>().forEach { testTask ->
            val includeIntegrationTests = if (project.hasProperty("includeIntegrationTests")) {
                project.property("includeIntegrationTests") != "false"
            } else if (project.hasProperty("excludeIntegrationTests")) {
                project.property("excludeIntegrationTests") == "false"
            } else true

            if (!includeIntegrationTests) {
                testTask.exclude("**/*IntegTest*")
            }
        }
    }
}




