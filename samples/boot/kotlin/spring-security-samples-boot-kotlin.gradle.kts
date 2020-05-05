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
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity5")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    testImplementation(project(":spring-security-test"))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict")
        jvmTarget = "1.8"
    }
}
