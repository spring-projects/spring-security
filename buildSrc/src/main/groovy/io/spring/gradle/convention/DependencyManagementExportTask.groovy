package io.spring.gradle.convention

import org.gradle.api.Project
import org.gradle.api.artifacts.component.ModuleComponentSelector
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.Properties;

import org.gradle.api.DefaultTask;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.tasks.TaskAction;

import io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension;

public class DependencyManagementExportTask extends DefaultTask {
	@Internal
	def projects;

	@Input
	String getProjectNames() {
		return projects*.name
	}

	@TaskAction
	public void dependencyManagementExport() throws IOException {
		def projects = this.projects ?: project.subprojects + project
		def configurations = projects*.configurations*.findAll { ['testRuntime','integrationTestRuntime','grettyRunnerTomcat8','ajtools'].contains(it.name) }
		def dependencyResults = configurations*.incoming*.resolutionResult*.allDependencies.flatten()
		def moduleVersionVersions = dependencyResults.findAll { r -> r.requested instanceof ModuleComponentSelector }.collect { r-> r.selected.moduleVersion }

		def projectDependencies = projects.collect { p-> "${p.group}:${p.name}:${p.version}".toString() } as Set
		def dependencies = moduleVersionVersions.collect { d ->
			"${d.group}:${d.name}:${d.version}".toString()
		}.sort() as Set

		println ''
		println ''
		println 'dependencyManagement {'
		println '\tdependencies {'
		dependencies.findAll { d-> !projectDependencies.contains(d)}.each {
			println "\t\tdependency '$it'"
		}
		println '\t}'
		println '}'
		println ''
		println ''
		println 'TIP Use this to find duplicates:\n$ sort gradle/dependency-management.gradle| uniq -c | grep -v \'^\\s*1\''
		println ''
		println ''
	}

	void setOutputFile(File file) throws IOException {
		this.output = new FileOutputStream(file);
	}
}
