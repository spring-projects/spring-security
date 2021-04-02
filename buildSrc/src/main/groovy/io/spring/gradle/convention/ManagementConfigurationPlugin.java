package io.spring.gradle.convention;

import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;

/**
 * https://github.com/gradle/gradle/issues/7576#issuecomment-434637595
 * @author Rob Winch
 */
public class ManagementConfigurationPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		Configuration management = project.getConfigurations()
			.create("management", new Action<Configuration>() {
				@Override
				public void execute(Configuration configuration) {
					configuration.setCanBeResolved(false);
					configuration.setCanBeConsumed(false);
					configuration.setDescription("Used for setting Gradle constraints that impact all configurations that can be resolved");
				}
			});
		project.getConfigurations().all(new Action<Configuration>() {
			@Override
			public void execute(Configuration configuration) {
				if (configuration.isCanBeResolved()) {
					configuration.extendsFrom(management);
				}
			}
		});
	}
}
