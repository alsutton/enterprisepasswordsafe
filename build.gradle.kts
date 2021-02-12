import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.api.tasks.testing.logging.TestExceptionFormat

buildscript {
    repositories {
        mavenCentral()
        jcenter()
    }

    dependencies {
        classpath("com.bmuschko:gradle-tomcat-plugin:2.5")
        classpath("org.junit.platform:junit-platform-gradle-plugin:1.2.0")
    }
}

plugins {
    java
    war
    id("com.bmuschko.tomcat") version "2.5"
    id("net.ltgt.errorprone") version "1.3.0"
    id("com.github.ben-manes.versions") version "0.36.0"
    jacoco
}

repositories {
    mavenCentral()
}

val junitVersion="5.7.0"
val mockitoVersion="3.7.7"

dependencies {
    implementation("com.sun.mail:javax.mail:1.6.2")
    implementation("com.sun.mail:smtp:2.0.0")
    implementation("commons-codec:commons-codec:1.15")
    implementation("commons-fileupload:commons-fileupload:1.4")
    implementation("javax.servlet:javax.servlet-api:4.0.+")
    implementation("javax.servlet.jsp:jsp-api:2.2.+")
    implementation("org.apache.commons:commons-collections4:4.4")
    implementation("org.apache.commons:commons-csv:1.8")
    implementation("org.apache.commons:commons-dbcp2:2.8.0")
    implementation("org.bouncycastle:bctls-jdk15on:1.68")

    runtimeOnly("opensymphony:sitemesh:2.4.2")
    runtimeOnly("javax.servlet:jstl:1.2")
    runtimeOnly("org.apache.derby:derby:10.15.2.0")
    runtimeOnly("org.apache.derby:derbytools:10.15.2.0")
    runtimeOnly("org.mariadb.jdbc:mariadb-java-client:2.6.2")

    testImplementation("org.junit.jupiter:junit-jupiter-api:${junitVersion}")
    testImplementation("org.mockito:mockito-core:${mockitoVersion}")
    testImplementation("org.mockito:mockito-junit-jupiter:${mockitoVersion}")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${junitVersion}")
    testCompileOnly("net.sourceforge.htmlunit:htmlunit:2.46.0")

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
