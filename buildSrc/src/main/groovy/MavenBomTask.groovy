import groovy.xml.MarkupBuilder

import org.gradle.api.DefaultTask
import org.gradle.api.Project
import org.gradle.api.tasks.*

public class MavenBomTask extends DefaultTask {

	Set<Project> projects

	File bomFile


	public MavenBomTask() {
		this.group = "Generate"
		this.description = "Generates a Maven Build of Materials (BOM). See https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Importing_Dependencies"
		this.projects = project.subprojects
		this.bomFile = project.file("${->project.buildDir}/maven-bom/${->project.name}-${->project.version}.txt")
	}

	@TaskAction
	public void configureBom() {
		project.configurations.archives.artifacts.clear()

		bomFile.parentFile.mkdirs()
		bomFile.write("Maven Build of Materials (BOM). See https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Importing_Dependencies")
		project.artifacts {
			// work around GRADLE-2406 by attaching text artifact
			archives(bomFile)
		}
		project.install {
			repositories.mavenInstaller {
				customizePom(pom)
			}
		}

		project.uploadArchives {
			repositories.mavenDeployer {
				customizePom(pom)
			}
		}
	}

	public void customizePom(pom) {
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
