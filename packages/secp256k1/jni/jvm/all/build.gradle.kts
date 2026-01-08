import org.gradle.kotlin.dsl.register

plugins {
    `java-library`
    id("org.jetbrains.dokka")
    `maven-publish`
}

dependencies {
    api(project(":packages:secp256k1:jni:jvm:darwin"))
    api(project(":packages:secp256k1:jni:jvm:linux"))
    api(project(":packages:secp256k1:jni:jvm:mingw"))
}

publishing {
    publications {
        create<MavenPublication>("jvm") {
            artifactId = "secp256k1-kmp-jni-jvm"
            from(components["java"])
            val sourcesJar = tasks.register<Jar>("sourcesJar") {
                archiveClassifier.set("sources")
            }
            artifact(sourcesJar)
        }
    }
}
