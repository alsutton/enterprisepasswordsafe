import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    java
    war
    id("com.bmuschko.tomcat") version "2.5"
    jacoco
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.sun.mail:javax.mail:1.6.2")
    implementation("com.sun.mail:smtp:1.6.5")
    implementation("commons-codec:commons-codec:1.14")
    implementation("commons-fileupload:commons-fileupload:1.3.3")
    implementation("javax.servlet:javax.servlet-api:4.0.+")
    implementation("javax.servlet.jsp:jsp-api:2.2.+")
    implementation("org.apache.commons:commons-collections4:4.4")
    implementation("org.apache.commons:commons-csv:1.8")
    implementation("org.apache.commons:commons-dbcp2:2.7.0")
    implementation("org.bouncycastle:bctls-jdk15on:1.65")

    runtimeOnly("opensymphony:sitemesh:2.4.2")
    runtimeOnly("javax.servlet:jstl:1.2")
    runtimeOnly("org.apache.derby:derby:10.15.2.0")
    runtimeOnly("org.apache.derby:derbytools:10.15.2.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.6.2")
    testImplementation("org.mockito:mockito-core:2.28.2")
    testImplementation("org.mockito:mockito-junit-jupiter:3.5.2")
    testCompileOnly("net.sourceforge.htmlunit:htmlunit:2.39.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.6.2")
}

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

tasks.withType<Test> {
    useJUnitPlatform()

    testLogging {
        events = mutableSetOf(TestLogEvent.FAILED, TestLogEvent.PASSED, TestLogEvent.SKIPPED)
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