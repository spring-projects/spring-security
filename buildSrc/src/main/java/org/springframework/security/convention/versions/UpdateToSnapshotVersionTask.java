/*
 * Copyright 2019-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.convention.versions;

import org.gradle.api.DefaultTask;
import org.gradle.api.Project;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class UpdateToSnapshotVersionTask extends DefaultTask {

	private static final String RELEASE_VERSION_PATTERN = "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-M\\d+|-RC\\d+)?$";

	@TaskAction
	public void updateToSnapshotVersion() {
		String currentVersion = getProject().getVersion().toString();
		File gradlePropertiesFile = getProject().getRootProject().file(Project.GRADLE_PROPERTIES);
		if (!gradlePropertiesFile.exists()) {
			return;
		}
		String nextVersion = calculateNextSnapshotVersion(currentVersion);
		System.out.println("Updating the project version in " + Project.GRADLE_PROPERTIES + " from " + currentVersion
				+ " to " + nextVersion);
		FileUtils.replaceFileText(gradlePropertiesFile, (gradlePropertiesText) -> {
			gradlePropertiesText = gradlePropertiesText.replace("version=" + currentVersion, "version=" + nextVersion);
			return gradlePropertiesText;
		});
	}

	private String calculateNextSnapshotVersion(String currentVersion) {
		Pattern releaseVersionPattern = Pattern.compile(RELEASE_VERSION_PATTERN);
		Matcher releaseVersion = releaseVersionPattern.matcher(currentVersion);

		if (releaseVersion.find()) {
			String majorSegment = releaseVersion.group(1);
			String minorSegment = releaseVersion.group(2);
			String patchSegment = releaseVersion.group(3);
			String modifier = releaseVersion.group(4);
			if (modifier == null) {
				patchSegment = String.valueOf(Integer.parseInt(patchSegment) + 1);
			}
			System.out.println("modifier = " + modifier);
			return String.format("%s.%s.%s-SNAPSHOT", majorSegment, minorSegment, patchSegment);
		}
		else {
			throw new IllegalStateException(
					"Cannot calculate next snapshot version because the current project version does not conform to the expected format");
		}
	}

}
