buildscript {
    repositories {
        mavenCentral()
    }

    dependencies {
        classpath("com.bmuschko:gradle-tomcat-plugin:2.5")
    }
}

plugins {
    war
    id("com.bmuschko.tomcat") version "2.5"
    id("net.ltgt.errorprone")
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

    implementation(project(":lib:authentication"))
    implementation(project(":lib:cryptography"))
    implementation(project(":lib:logging"))
    implementation(project(":lib:model"))
    implementation(project(":lib:passwordprocessor"))

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

    errorprone("com.google.errorprone:error_prone_core:2.5.1")
}
