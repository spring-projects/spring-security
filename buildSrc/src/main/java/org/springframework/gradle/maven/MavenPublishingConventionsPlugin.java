package org.springframework.gradle.maven;

import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.publish.PublishingExtension;
import org.gradle.api.publish.VariantVersionMappingStrategy;
import org.gradle.api.publish.VersionMappingStrategy;
import org.gradle.api.publish.maven.MavenPom;
import org.gradle.api.publish.maven.MavenPomDeveloperSpec;
import org.gradle.api.publish.maven.MavenPomIssueManagement;
import org.gradle.api.publish.maven.MavenPomLicenseSpec;
import org.gradle.api.publish.maven.MavenPomOrganization;
import org.gradle.api.publish.maven.MavenPomScm;
import org.gradle.api.publish.maven.MavenPublication;
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin;

public class MavenPublishingConventionsPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getPlugins().withType(MavenPublishPlugin.class).all(new Action<MavenPublishPlugin>() {
			@Override
			public void execute(MavenPublishPlugin mavenPublish) {
				PublishingExtension publishing = project.getExtensions().getByType(PublishingExtension.class);
				publishing.getPublications().withType(MavenPublication.class)
						.all((mavenPublication) -> {
							mavenPublication.versionMapping(new Action<VersionMappingStrategy>() {
								@Override
								public void execute(VersionMappingStrategy versionStrategy) {
									versionStrategy.usage("java-runtime", new Action<VariantVersionMappingStrategy>() {
										@Override
										public void execute(VariantVersionMappingStrategy mappingStrategy) {
											mappingStrategy.fromResolutionResult();
										}
									});
								}
							});
							MavenPublishingConventionsPlugin.this.customizePom(mavenPublication.getPom(), project);
						});
				MavenPublishingConventionsPlugin.this.customizeJavaPlugin(project);
			}
		});
	}

	private void customizePom(MavenPom pom, Project project) {
		pom.getUrl().set("https://spring.io/projects/spring-security");
		pom.getName().set(project.provider(project::getName));
		pom.getDescription().set(project.provider(project::getDescription));
		pom.organization(this::customizeOrganization);
		pom.licenses(this::customizeLicences);
		pom.developers(this::customizeDevelopers);
		pom.scm(this::customizeScm);
		pom.issueManagement(this::customizeIssueManagement);
	}

	private void customizeOrganization(MavenPomOrganization organization) {
		organization.getName().set("Pivotal Software, Inc.");
		organization.getUrl().set("https://spring.io");
	}

	private void customizeLicences(MavenPomLicenseSpec licences) {
		licences.license((licence) -> {
			licence.getName().set("Apache License, Version 2.0");
			licence.getUrl().set("https://www.apache.org/licenses/LICENSE-2.0");
		});
	}

	private void customizeDevelopers(MavenPomDeveloperSpec developers) {
		developers.developer((developer) -> {
			developer.getName().set("Pivotal");
			developer.getEmail().set("info@pivotal.io");
			developer.getOrganization().set("Pivotal Software, Inc.");
			developer.getOrganizationUrl().set("https://www.spring.io");
		});
	}

	private void customizeScm(MavenPomScm scm) {
		scm.getConnection().set("scm:git:git://github.com/spring-projects/spring-security.git");
		scm.getDeveloperConnection().set("scm:git:ssh://git@github.com/spring-projects/spring-security.git");
		scm.getUrl().set("https://github.com/spring-projects/spring-security");
	}

	private void customizeIssueManagement(MavenPomIssueManagement issueManagement) {
		issueManagement.getSystem().set("GitHub");
		issueManagement.getUrl().set("https://github.com/spring-projects/spring-security/issues");
	}

	private void customizeJavaPlugin(Project project) {
		project.getPlugins().withType(JavaPlugin.class).all((javaPlugin) -> {
			JavaPluginExtension extension = project.getExtensions().getByType(JavaPluginExtension.class);
			extension.withJavadocJar();
			extension.withSourcesJar();
		});
	}
}
