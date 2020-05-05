import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("io.spring.convention.spring-sample-boot")
	kotlin("jvm")
	kotlin("plugin.spring") version "1.3.71"
}

repositories {
	mavenCentral()
}

dependencies {
    implementation(project(":spring-security-core"))
    implementation(project(":spring-security-config"))
    implementation(project(":spring-security-web"))
	implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity5")
	implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
	implementation("org.jetbrains.kotlin:kotlin-reflect")
	implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
	implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")

    testImplementation(project(":spring-security-test"))
	testImplementation("org.springframework.boot:spring-boot-starter-test") {
		exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
	}
	testImplementation("io.projectreactor:reactor-test")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
	kotlinOptions {
		freeCompilerArgs = listOf("-Xjsr305=strict")
		jvmTarget = "1.8"
	}
}
