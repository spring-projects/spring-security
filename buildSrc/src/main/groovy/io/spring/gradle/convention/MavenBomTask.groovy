package io.spring.gradle.convention

import org.gradle.api.DefaultTask
import org.gradle.api.Project
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

public class MavenBomTask extends DefaultTask {

	@Internal
	Set<Project> projects = []

	@OutputFile
	File bomFile

	@Input
	Set<String> getProjectNames() {
		return projects*.name as Set
	}

	public MavenBomTask() {
		this.group = "Generate"
		this.description = "Generates a Maven Build of Materials (BOM). See https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Importing_Dependencies"
		this.projects = project.subprojects
		this.bomFile = project.file("${->project.buildDir}/maven-bom/${->project.name}-${->project.version}.txt")
		this.outputs.upToDateWhen { false }
	}

	@TaskAction
	public void configureBom() {
//		project.configurations.archives.artifacts.clear()
		bomFile.parentFile.mkdirs()
		bomFile.write("Maven Build of Materials (BOM). See https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Importing_Dependencies")
		project.artifacts {
			// work around GRADLE-2406 by attaching text artifact
			archives(bomFile)
		}
		project.install {
			repositories.mavenInstaller {
				pom.whenConfigured {
					packaging = "pom"
					withXml {
						asNode().children().last() + {
							delegate.dependencyManagement {
								delegate.dependencies {
									projects.sort { dep -> "$dep.group:$dep.name" }.each { p ->

										delegate.dependency {
											delegate.groupId(p.group)
											delegate.artifactId(p.name)
											delegate.version(p.version)
										}
									}
								}
							}
						}
					}
				}
			}
		}
		project.uploadArchives {
			repositories.mavenDeployer {
				pom.whenConfigured {
					packaging = "pom"
					withXml {
						asNode().children().last() + {
							delegate.dependencyManagement {
								delegate.dependencies {
									projects.sort { dep -> "$dep.group:$dep.name" }.each { p ->

										delegate.dependency {
											delegate.groupId(p.group)
											delegate.artifactId(p.name)
											delegate.version(p.version)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
