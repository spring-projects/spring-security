package org.springframework.gradle.maven;


import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPlatformPlugin;
import org.gradle.api.publish.PublishingExtension;
import org.gradle.api.publish.maven.MavenPublication;
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin;

public class PublishAllJavaComponentsPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getPlugins().withType(MavenPublishPlugin.class).all((mavenPublish) -> {
			PublishingExtension publishing = project.getExtensions().getByType(PublishingExtension.class);
			publishing.getPublications().create("maven", MavenPublication.class, new Action<MavenPublication>() {
				@Override
				public void execute(MavenPublication maven) {
					project.getPlugins().withType(JavaPlatformPlugin.class)
							.all((javaPlugin) -> project.getComponents()
									.matching((component) -> component.getName().equals("javaPlatform"))
									.all((javaComponent) -> maven.from(javaComponent)));
				}
			});
		});
	}
}
