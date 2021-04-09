import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.api.tasks.testing.logging.TestExceptionFormat

buildscript {
    repositories {
        mavenCentral()
    }
}

repositories {
    mavenCentral()
}

plugins {
    java
    id("net.ltgt.errorprone")
    jacoco
}

dependencies {
    errorprone("com.google.errorprone:error_prone_core:2.5.1")
}

tasks.withType<JavaCompile>().configureEach {
    options.errorprone.allErrorsAsWarnings.set(false)
}