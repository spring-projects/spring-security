package org.springframework.gradle;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

public class CopyPropertiesPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		copyPropertyFromRootProjectTo("group", project);
		copyPropertyFromRootProjectTo("version", project);
		copyPropertyFromRootProjectTo("description", project);
	}


	private void copyPropertyFromRootProjectTo(String propertyName, Project project) {
		Project rootProject = project.getRootProject();
		Object property = rootProject.findProperty(propertyName);
		if(property != null) {
			project.setProperty(propertyName, property);
		}
	}
}
