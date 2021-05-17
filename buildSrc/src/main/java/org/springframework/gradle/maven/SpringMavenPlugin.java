package org.springframework.gradle.maven;

import io.spring.gradle.convention.ArtifactoryPlugin;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.PluginManager;

public class SpringMavenPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(SpringSigningPlugin.class);
		pluginManager.apply(SpringMavenPlugin.class);
		pluginManager.apply(MavenPublishingConventionsPlugin.class);
		pluginManager.apply(PublishAllJavaComponentsPlugin.class);
		pluginManager.apply(PublishLocalPlugin.class);
		pluginManager.apply(PublishArtifactsPlugin.class);
		pluginManager.apply(ArtifactoryPlugin.class);
	}
}
