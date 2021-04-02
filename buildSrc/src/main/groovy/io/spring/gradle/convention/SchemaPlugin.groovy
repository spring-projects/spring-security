package io.spring.gradle.convention

import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.tasks.bundling.Zip
import org.gradle.api.Plugin
import org.gradle.api.Project

public class SchemaPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		project.getPluginManager().apply(SchemaZipPlugin)
		project.getPluginManager().apply(SchemaDeployPlugin)
	}
}