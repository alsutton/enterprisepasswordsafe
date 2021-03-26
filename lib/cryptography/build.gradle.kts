buildscript {
    repositories {
        mavenCentral()
    }
}

plugins {
    java
}

repositories {
    maven {
        url = uri("https://maven.alsutton.com/")
    }
    mavenCentral()
}

val immutablesVersion = "2.8.2"
val hibernateVersion = "5.4.28.Final"
dependencies {
    annotationProcessor("org.immutables:value:${immutablesVersion}")

    compileOnly("org.immutables:value:${immutablesVersion}")

    implementation("com.alsutton:java-cryptography-wrapper:1.0")

    implementation("org.bouncycastle:bcprov-jdk15on:1.68")
    implementation("org.hibernate:hibernate-core:${hibernateVersion}")
    implementation("org.hibernate:hibernate-ehcache:${hibernateVersion}")
}
