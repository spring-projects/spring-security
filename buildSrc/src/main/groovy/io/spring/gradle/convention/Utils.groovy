package io.spring.gradle.convention;

import org.gradle.api.Project;

public class Utils {

	static String getProjectName(Project project) {
		String projectName = project.getRootProject().getName();
		if(projectName.endsWith("-build")) {
			projectName = projectName.substring(0, projectName.length() - "-build".length());
		}
		return projectName;
	}

	static boolean isSnapshot(Project project) {
		String projectVersion = projectVersion(project)
		return projectVersion.matches('^.*([.-]BUILD)?-SNAPSHOT$')
	}

	static boolean isMilestone(Project project) {
		String projectVersion = projectVersion(project)
		return projectVersion.matches('^.*[.-]M\\d+$') || projectVersion.matches('^.*[.-]RC\\d+$')
	}

	static boolean isRelease(Project project) {
		return !(isSnapshot(project) || isMilestone(project))
	}

	private static String projectVersion(Project project) {
		return String.valueOf(project.getVersion());
	}

	private Utils() {}
}
