import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

/**
 * SARO JWT
 *
 * + publish
 * 1. gradle publish
 * 2. https://oss.sonatype.org/
 * 3. Staging Repositories
 * 4. Close -> Release
 *
 * + publish setting
 * 1. create gpg
 * 2. set gradle.properties
 *    - ex windows path) C:/Users/<USER_NAME>/.gradle/gradle.properties
 *    sonatype.username=<username>
 *    sonatype.password=<password>
 *    signing.keyId=<last 8/16 chars in key>
 *    signing.password=<secret>
 *    signing.secretKeyRingFile=<path of secring.gpg>
 *
 * + you can use "User Token" instead of id & password.
 *     - https://oss.sonatype.org -> profile -> User Token
 *
 * @See
 * https://github.com/saro-lab/jwt
 * https://docs.gradle.org/current/userguide/publishing_maven.html
 * https://docs.gradle.org/current/userguide/signing_plugin.html#signing_plugin
 * windows -> pgp4win
 * gpg --gen-key
 * gpg --list-keys --keyid-format short
 * gpg --export-secret-keys -o secring.gpg
 */

plugins {
	val kotlinVersion = "1.7.21"
	kotlin("jvm") version kotlinVersion
	kotlin("kapt") version kotlinVersion
	signing
	`maven-publish`
}

val jwtGroupId = "me.saro"
val jwtArtifactId = "jwt"
val jwtVersion = "2.0.1"

configure<JavaPluginExtension> {
	sourceCompatibility = JavaVersion.VERSION_11
	targetCompatibility = JavaVersion.VERSION_11
}

repositories {
	mavenCentral()
}

java {
	withJavadocJar()
	withSourcesJar()
}

dependencies {
	// koltin
	//implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
	//implementation("org.jetbrains.kotlin:kotlin-reflect")

	// jackson
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.14.0")

	// test
	val junitVer = "5.9.0"
	testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVer")
	testImplementation("org.junit.jupiter:junit-jupiter-engine:$junitVer")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

publishing {
	publications {
		create<MavenPublication>("maven") {

			groupId = jwtGroupId
			artifactId = jwtArtifactId
			version = jwtVersion

			from(components["java"])

			repositories {
				maven {
					credentials {
						try {
							username = project.property("sonatype.username").toString()
							password = project.property("sonatype.password").toString()
						} catch (e: Exception) {
							println("warn: " + e.message)
						}
					}
					val releasesRepoUrl = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
					val snapshotsRepoUrl = uri("https://oss.sonatype.org/content/repositories/snapshots/")
					url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
				}
			}

			pom {
				name.set("SARO JWT")
				description.set("SARO JWT")
				url.set("https://saro.me")

				licenses {
					license {
						name.set("The Apache License, Version 2.0")
						url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
					}
				}
				developers {
					developer {
						name.set("PARK Yong Seo")
						email.set("j@saro.me")
					}
				}
				scm {
					connection.set("scm:git:git://github.com/saro-lab/jwt.git")
					developerConnection.set("scm:git:git@github.com:saro-lab/jwt.git")
					url.set("https://github.com/saro-lab/jwt")
				}
			}
		}
	}
}

signing {
	sign(publishing.publications["maven"])
}

tasks.withType<Javadoc>().configureEach {
	options {
		this as StandardJavadocDocletOptions
		addBooleanOption("Xdoclint:none", true)
	}
}

tasks.withType<KotlinCompile> {
	kotlinOptions {
		freeCompilerArgs = listOf("-Xjsr305=strict")
		jvmTarget = "11"
	}
}
