plugins {
    `java-library`
    `maven-publish`
    signing
    jacoco
    id("org.sonarqube") version "6.0.1.5171"
    id("pl.allegro.tech.build.axion-release") version "1.18.16"
    id("com.adarshr.test-logger") version "4.0.0"
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer:20220608.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.0")
}

group = "com.github.bgalek.security.svg"
version = scmVersion.version

java {
    withSourcesJar()
    withJavadocJar()
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

tasks {
    jar {
        manifest {
            attributes(mapOf("Implementation-Title" to project.name, "Implementation-Version" to project.version))
        }
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.jacocoTestReport {
    reports {
        xml.required = true
    }
}

publishing {
    publications {
        create<MavenPublication>("sonatype") {
            artifactId = "safe-svg"
            from(components["java"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }
            pom {
                name.set("safe-svg")
                description.set("Simple and lightweight library that helps to validate SVG files in security manners.")
                url.set("https://github.com/bgalek/safe-svg/")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("bgalek")
                        name.set("Bartosz Gałek")
                        email.set("bartosz@galek.com.pl")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/bgalek/safe-svg.git")
                    developerConnection.set("scm:git:ssh://github.com:bgalek/safe-svg.git")
                    url.set("https://github.com/bgalek/safe-svg/")
                }
            }
        }
    }
    repositories {
        maven {
            val releasesRepoUrl = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsRepoUrl = uri("https://oss.sonatype.org/content/repositories/snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {
            username.set(System.getenv("SONATYPE_USERNAME"))
            password.set(System.getenv("SONATYPE_PASSWORD"))
        }
    }
}

System.getenv("GPG_KEY_ID")?.let {
    signing {
        useInMemoryPgpKeys(
            System.getenv("GPG_KEY_ID"),
            System.getenv("GPG_PRIVATE_KEY"),
            System.getenv("GPG_PRIVATE_KEY_PASSWORD")
        )
        sign(publishing.publications)
    }
}
