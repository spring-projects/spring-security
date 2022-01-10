package org.springframework.gradle.antora;

import org.gradle.api.Action;
import org.gradle.api.GradleException;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.language.base.plugins.LifecycleBasePlugin;

public class CheckAntoraVersionPlugin implements Plugin<Project> {
	public static final String ANTORA_CHECK_VERSION_TASK_NAME = "antoraCheckVersion";

	@Override
	public void apply(Project project) {
		TaskProvider<CheckAntoraVersionTask> antoraCheckVersion = project.getTasks().register(ANTORA_CHECK_VERSION_TASK_NAME, CheckAntoraVersionTask.class, new Action<CheckAntoraVersionTask>() {
			@Override
			public void execute(CheckAntoraVersionTask antoraCheckVersion) {
				antoraCheckVersion.setGroup(LifecycleBasePlugin.VERIFICATION_GROUP);
				antoraCheckVersion.setDescription("Checks the antora.yml version properties match the Gradle version");
				antoraCheckVersion.getAntoraVersion().convention(project.provider(() -> getDefaultAntoraVersion(project)));
				antoraCheckVersion.getAntoraPrerelease().convention(project.provider(() -> getDefaultAntoraPrerelease(project)));
				antoraCheckVersion.getAntoraYmlFile().fileProvider(project.provider(() -> project.file("antora.yml")));
			}
		});
		project.getPlugins().withType(LifecycleBasePlugin.class, new Action<LifecycleBasePlugin>() {
			@Override
			public void execute(LifecycleBasePlugin lifecycleBasePlugin) {
				project.getTasks().named(LifecycleBasePlugin.CHECK_TASK_NAME).configure(new Action<Task>() {
					@Override
					public void execute(Task check) {
						check.dependsOn(antoraCheckVersion);
					}
				});
			}
		});
	}

	private static String getDefaultAntoraVersion(Project project) {
		String projectVersion = getProjectVersion(project);
		int preReleaseIndex = getSnapshotIndex(projectVersion);
		return isSnapshot(projectVersion) ? projectVersion.substring(0, preReleaseIndex) : projectVersion;
	}

	private static String getDefaultAntoraPrerelease(Project project) {
		String projectVersion = getProjectVersion(project);
		if (isSnapshot(projectVersion)) {
			int preReleaseIndex = getSnapshotIndex(projectVersion);
			return projectVersion.substring(preReleaseIndex);
		}
		if (isPreRelease(projectVersion)) {
			return Boolean.TRUE.toString();
		}
		return null;
	}

	private static String getProjectVersion(Project project) {
		Object projectVersion = project.getVersion();
		if (projectVersion == null) {
			throw new GradleException("Please define antoraVersion and antoraPrerelease on " + ANTORA_CHECK_VERSION_TASK_NAME + " or provide a Project version so they can be defaulted");
		}
		return String.valueOf(projectVersion);
	}

	private static boolean isSnapshot(String projectVersion) {
		return getSnapshotIndex(projectVersion) >= 0;
	}

	private static int getSnapshotIndex(String projectVersion) {
		return projectVersion.lastIndexOf("-SNAPSHOT");
	}

	private static boolean isPreRelease(String projectVersion) {
		return projectVersion.lastIndexOf("-") >= 0;
	}
}
