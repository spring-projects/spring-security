package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlatformPlugin
import org.sonarqube.gradle.SonarQubePlugin
import org.springframework.gradle.CopyPropertiesPlugin
import org.springframework.gradle.maven.SpringMavenPlugin

public class MavenBomPlugin implements Plugin<Project> {
	static String MAVEN_BOM_TASK_NAME = "mavenBom"

	public void apply(Project project) {
		project.plugins.apply(JavaPlatformPlugin)
		project.plugins.apply(SpringMavenPlugin)
		project.plugins.apply(CopyPropertiesPlugin)
	}
}
