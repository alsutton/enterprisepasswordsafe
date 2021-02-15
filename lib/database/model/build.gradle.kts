import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.api.tasks.testing.logging.TestExceptionFormat

buildscript {
    repositories {
        mavenCentral()
    }
}

plugins {
    java
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.hibernate:hibernate-core:5.4.28.Final")
}
