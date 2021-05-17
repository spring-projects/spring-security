package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.sonarqube.gradle.SonarQubePlugin
import org.springframework.gradle.maven.SpringMavenPlugin

public class MavenBomPlugin implements Plugin<Project> {
	static String MAVEN_BOM_TASK_NAME = "mavenBom"

	public void apply(Project project) {
		project.configurations {
			archives
		}
		project.plugins.apply(SpringMavenPlugin)

		project.group = project.rootProject.group
		project.task(MAVEN_BOM_TASK_NAME, type: MavenBomTask, group: 'Generate', description: 'Configures the pom as a Maven Build of Materials (BOM)')
		project.tasks.uploadArchives.dependsOn project.mavenBom
		project.tasks.artifactoryPublish.dependsOn project.mavenBom

		project.plugins.withType(SonarQubePlugin) {
			project.sonarqube.skipProject = true
		}

		project.rootProject.allprojects.each { p ->
			p.plugins.withType(SpringMavenPlugin) {
				if (!project.name.equals(p.name)) {
					project.mavenBom.projects.add(p)
				}
			}
		}

		def deployArtifacts = project.task("deployArtifacts")
		deployArtifacts.group = 'Deploy tasks'
		deployArtifacts.description = "Deploys the artifacts to either Artifactor or Maven Central"
		if(Utils.isRelease(project)) {
			deployArtifacts.dependsOn project.tasks.uploadArchives
		} else {
			deployArtifacts.dependsOn project.tasks.artifactoryPublish
		}

		project.artifacts {
			archives project.mavenBom.bomFile
		}
	}
}
