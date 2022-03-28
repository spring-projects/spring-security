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
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.springframework.gradle.github.milestones.NextVersionYml;

public abstract class UpdateProjectVersionTask extends DefaultTask {

	@InputFile
	public abstract RegularFileProperty getNextVersionFile();

	@TaskAction
	public void checkReleaseDueToday() throws FileNotFoundException {
		File nextVersionFile = getNextVersionFile().getAsFile().get();
		Yaml yaml = new Yaml(new Constructor(NextVersionYml.class));
		NextVersionYml nextVersionYml = yaml.load(new FileInputStream(nextVersionFile));
		String nextVersion = nextVersionYml.getVersion();
		if (nextVersion == null) {
			throw new IllegalArgumentException(
					"Could not find version property in provided file " + nextVersionFile.getName());
		}
		String currentVersion = getProject().getVersion().toString();
		File gradlePropertiesFile = getProject().getRootProject().file(Project.GRADLE_PROPERTIES);
		if (!gradlePropertiesFile.exists()) {
			return;
		}
		System.out.println("Updating the project version in " + Project.GRADLE_PROPERTIES + " from " + currentVersion
				+ " to " + nextVersion);
		FileUtils.replaceFileText(gradlePropertiesFile, (gradlePropertiesText) -> {
			gradlePropertiesText = gradlePropertiesText.replace("version=" + currentVersion, "version=" + nextVersion);
			return gradlePropertiesText;
		});
	}

}
