import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.api.tasks.testing.logging.TestExceptionFormat

buildscript {
    repositories {
        mavenCentral()
    }

    dependencies {
        classpath("org.junit.platform:junit-platform-gradle-plugin:1.2.0")
    }
}

plugins {
    java
    id("net.ltgt.errorprone")
    jacoco
}

repositories {
    maven {
        url = uri("https://maven.alsutton.com/")
        content {
            includeGroup("com.alsutton")
        }
    }
    mavenCentral()
}

val junitVersion="5.7.0"
val mockitoVersion="3.7.7"
val immutablesVersion = "2.8.2"
dependencies {
    annotationProcessor("org.immutables:value:${immutablesVersion}")

    compileOnly("org.immutables:value:${immutablesVersion}")

    implementation("com.alsutton:java-cryptography-wrapper:1.0")
    implementation(project(":lib:cryptography"))
    implementation(project(":lib:model"))
    implementation("com.sun.mail:javax.mail:1.6.2")
    implementation("com.sun.mail:smtp:2.0.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:${junitVersion}")
    testImplementation("org.mockito:mockito-core:${mockitoVersion}")
    testImplementation("org.mockito:mockito-junit-jupiter:${mockitoVersion}")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${junitVersion}")

    errorprone("com.google.errorprone:error_prone_core:2.5.1")
}

tasks.withType<JavaCompile>().configureEach {
    options.errorprone.allErrorsAsWarnings.set(false)
}

tasks.withType<Test> {
    useJUnitPlatform()

    testLogging {
        events = mutableSetOf(TestLogEvent.FAILED, TestLogEvent.PASSED, TestLogEvent.SKIPPED)
        exceptionFormat = TestExceptionFormat.FULL
    }
}

jacoco {
    toolVersion = "0.8.2"
}

tasks.withType<JacocoReport> {
    group = "Reporting"
    reports {
        xml.isEnabled = true
        csv.isEnabled =  false
        html.destination = file("${buildDir}/reports/coverage")
    }
}
