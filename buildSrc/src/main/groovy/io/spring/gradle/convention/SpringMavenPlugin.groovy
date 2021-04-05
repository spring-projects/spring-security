package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.XmlProvider
import org.gradle.api.artifacts.component.ModuleComponentSelector
import org.gradle.api.artifacts.maven.MavenDeployment
import org.gradle.api.artifacts.maven.MavenPom
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.plugins.JavaBasePlugin
import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.plugins.JavaPluginConvention
import org.gradle.api.plugins.MavenPlugin
import org.gradle.api.tasks.SourceSet
import org.gradle.api.tasks.bundling.Jar
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.plugins.signing.SigningPlugin
import org.slf4j.Logger
import org.slf4j.LoggerFactory

public class SpringMavenPlugin implements Plugin<Project> {
	private static final String ARCHIVES = "archives";
	Logger logger = LoggerFactory.getLogger(getClass());

	@Override
	public void apply(Project project) {
		project.getPluginManager().apply(JavaPlugin.class);
		project.getPluginManager().apply(MavenPlugin.class);
		project.getPluginManager().apply(SigningPlugin.class);

		Javadoc javadoc = (Javadoc) project.getTasks().findByPath("javadoc");
		Jar javadocJar = project.getTasks().create("javadocJar", Jar.class);
		javadocJar.setClassifier("javadoc");
		javadocJar.from(javadoc);

		JavaPluginConvention java = project.getConvention().getPlugin(JavaPluginConvention.class);
		SourceSet mainSourceSet = java.getSourceSets().getByName("main");
		Jar sourcesJar = project.getTasks().create("sourcesJar", Jar.class);
		sourcesJar.setClassifier("sources");
		sourcesJar.from(mainSourceSet.getAllSource());

		project.getArtifacts().add(ARCHIVES, javadocJar);
		project.getArtifacts().add(ARCHIVES, sourcesJar);

		project.install {
			repositories.mavenInstaller {
				configurePom(project, pom)
			}
		}
		project.uploadArchives {
			repositories.mavenDeployer {
				configurePom(project, pom)
			}
		}

		inlineDependencyManagement(project);

		def hasSigningKey = project.hasProperty("signing.keyId") || project.findProperty("signingKey")
		if(hasSigningKey && Utils.isRelease(project)) {
			sign(project)
		}

		project.getPluginManager().apply("io.spring.convention.ossrh");
	}

	private void inlineDependencyManagement(Project project) {
		project.install {
			repositories.mavenInstaller {
				configurePomForInlineDependencies(project, pom)
			}
		}
		project.uploadArchives {
			repositories.mavenDeployer {
				configurePomForInlineDependencies(project, pom)
			}
		}
	}

	private void configurePomForInlineDependencies(Project project, MavenPom pom) {
		pom.withXml { XmlProvider xml ->
			project.plugins.withType(JavaBasePlugin) {
				def dependencies = xml.asNode()?.dependencies?.dependency
				def configuredDependencies = project.configurations.findAll{ it.canBeResolved && it.canBeConsumed }*.incoming*.resolutionResult*.allDependencies.flatten()
				dependencies?.each { Node dep ->
					def group = dep.groupId.text()
					def name = dep.artifactId.text()

					ResolvedDependencyResult resolved = configuredDependencies.find { r ->
						(r.requested instanceof ModuleComponentSelector) &&
								(r.requested.group == group) &&
								(r.requested.module == name)
					}

					if (!resolved) {
						return
					}

					def versionNode = dep.version
					if (!versionNode) {
						dep.appendNode('version')
					}
					def moduleVersion = resolved.selected.moduleVersion
					dep.groupId[0].value = moduleVersion.group
					dep.artifactId[0].value = moduleVersion.name
					dep.version[0].value = moduleVersion.version
				}
			}
		}
	}

	private void sign(Project project) {
		project.install {
			repositories {
				mavenDeployer {
					beforeDeployment { MavenDeployment deployment -> project.signing.signPom(deployment) }
				}
			}
		}

		project.uploadArchives {
			repositories {
				mavenDeployer {
					beforeDeployment { MavenDeployment deployment -> project.signing.signPom(deployment) }
				}
			}
		}

		project.signing {
			required { project.gradle.taskGraph.hasTask("uploadArchives") }
			def signingKeyId = project.findProperty("signingKeyId")
			def signingKey = project.findProperty("signingKey")
			def signingPassword = project.findProperty("signingPassword")
			if (signingKeyId) {
				useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
			} else if (signingKey) {
				useInMemoryPgpKeys(signingKey, signingPassword)
			}
			sign project.configurations.archives
		}
	}

	private static void configurePom(Project project, MavenPom pom) {
		pom.whenConfigured { p ->
			p.dependencies = p.dependencies.sort { dep ->
				"$dep.scope:$dep.optional:$dep.groupId:$dep.artifactId"
			}
		}

		pom.project {
			boolean isWar = project.hasProperty("war");
			String projectVersion = String.valueOf(project.getVersion());
			String projectName = Utils.getProjectName(project);

			if(isWar) {
				packaging = "war"
			}
			name = project.name
			description = project.name
			url = 'https://spring.io/spring-security'
			organization {
				name = 'spring.io'
				url = 'https://spring.io/'
			}
			licenses {
				license {
					name 'The Apache Software License, Version 2.0'
					url 'https://www.apache.org/licenses/LICENSE-2.0.txt'
					distribution 'repo'
					}
				}
			scm {
				url = 'https://github.com/spring-projects/spring-security'
				connection = 'scm:git:git://github.com/spring-projects/spring-security'
				developerConnection = 'scm:git:git://github.com/spring-projects/spring-security'
			}
			developers {
				developer {
					id = 'rwinch'
					name = 'Rob Winch'
					email = 'rwinch@pivotal.io'
				}
				developer {
					id = 'jgrandja'
					name = 'Joe Grandja'
					email = 'jgrandja@pivotal.io'
				}
			}

			if(isWar) {
				properties {
					'm2eclipse.wtp.contextRoot' '/'
				}
			}
			if (Utils.isSnapshot(project)) {
				repositories {
					repository {
						id 'spring-snapshot'
						url 'https://repo.spring.io/snapshot'
					}
				}
			}
			else if (Utils.isMilestone(project)) {
				repositories {
					repository {
						id 'spring-milestone'
						url 'https://repo.spring.io/milestone'
					}
				}
			}
		}
	}
}
