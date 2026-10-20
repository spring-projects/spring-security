package org.springframework.gradle.maven;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.plugins.PluginManager;

import io.spring.gradle.convention.ArtifactoryPlugin;
import io.spring.gradle.plugin.maven.SpringDeploymentRepositoryPublishPlugin;
import io.spring.gradle.plugin.maven.SpringMavenPublishPlugin;

public class SpringMavenPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(SpringMavenPublishPlugin.class);
		pluginManager.apply(SpringDeploymentRepositoryPublishPlugin.class);
		project.getPlugins().withType(JavaPlugin.class).all((javaPlugin) -> {
			JavaPluginExtension extension = project.getExtensions().getByType(JavaPluginExtension.class);
			extension.withJavadocJar();
			extension.withSourcesJar();
		});
		pluginManager.apply(PublishArtifactsPlugin.class);
		pluginManager.apply(ArtifactoryPlugin.class);
	}
}
