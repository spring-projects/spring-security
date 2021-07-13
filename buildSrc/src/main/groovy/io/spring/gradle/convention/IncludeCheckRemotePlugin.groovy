package io.spring.gradle.convention

import io.spring.gradle.IncludeRepoTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.provider.Property
import org.gradle.api.tasks.GradleBuild
import org.gradle.api.tasks.TaskProvider

class IncludeCheckRemotePlugin implements Plugin<Project> {
	@Override
	void apply(Project project) {
		IncludeCheckRemoteExtension extension = project.extensions.create('includeCheckRemote', IncludeCheckRemoteExtension)
		TaskProvider<IncludeRepoTask> includeRepoTask = project.tasks.register('includeRepo', IncludeRepoTask) { IncludeRepoTask it ->
			it.repository = extension.repository.get()
			it.ref = extension.ref.get()
		}
		project.tasks.register('checkRemote', GradleBuild) {
			it.dependsOn 'includeRepo'
			it.dir = includeRepoTask.get().outputDirectory
			it.tasks = extension.getTasks()
		}
	}

	abstract static class IncludeCheckRemoteExtension {
		/**
		 * Git repository to clone
		 */
		abstract Property<String> getRepository();
		/**
		 * Git ref to checkout
		 */
		abstract Property<String> getRef();
		/**
		 * Task to run in the repository
		 */
		List<String> tasks = ['check']

		void setTask(List<String> tasks) {
			this.tasks = tasks
		}
	}

}
