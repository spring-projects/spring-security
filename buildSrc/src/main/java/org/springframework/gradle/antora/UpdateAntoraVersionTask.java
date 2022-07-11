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

package org.springframework.gradle.antora;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;

import org.springframework.gradle.github.milestones.NextVersionYml;

public abstract class UpdateAntoraVersionTask extends DefaultTask {

	@TaskAction
	public void update() throws IOException {
		String projectVersion = getProject().getVersion().toString();
		File antoraYmlFile = getAntoraYmlFile().getAsFile().get();
		String updatedAntoraVersion = AntoraVersionUtils.getDefaultAntoraVersion(projectVersion);
		String updatedAntoraPrerelease = AntoraVersionUtils.getDefaultAntoraPrerelease(projectVersion);
		String updatedAntoraDisplayVersion = AntoraVersionUtils.getDefaultAntoraDisplayVersion(projectVersion);

		Representer representer = new Representer();
		representer.getPropertyUtils().setSkipMissingProperties(true);

		Yaml yaml = new Yaml(new Constructor(AntoraYml.class), representer);
		AntoraYml antoraYml = yaml.load(new FileInputStream(antoraYmlFile));

		System.out.println("Updating the version parameters in " + antoraYmlFile.getName() + " to version: "
				+ updatedAntoraVersion + ", prerelease: " + updatedAntoraPrerelease + ", display_version: "
				+ updatedAntoraDisplayVersion);
		antoraYml.setVersion(updatedAntoraVersion);
		antoraYml.setPrerelease(updatedAntoraPrerelease);
		antoraYml.setDisplay_version(updatedAntoraDisplayVersion);

		FileWriter outputWriter = new FileWriter(antoraYmlFile);
		getYaml().dump(antoraYml, outputWriter);
	}

	@InputFile
	public abstract RegularFileProperty getAntoraYmlFile();

	public static class AntoraYml {

		private String name;

		private String version;

		private String prerelease;

		private String display_version;

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getVersion() {
			return version;
		}

		public void setVersion(String version) {
			this.version = version;
		}

		public String getPrerelease() {
			return prerelease;
		}

		public void setPrerelease(String prerelease) {
			this.prerelease = prerelease;
		}

		public String getDisplay_version() {
			return display_version;
		}

		public void setDisplay_version(String display_version) {
			this.display_version = display_version;
		}

	}

	private Yaml getYaml() {
		Representer representer = new Representer() {
			@Override
			protected NodeTuple representJavaBeanProperty(Object javaBean,
					org.yaml.snakeyaml.introspector.Property property, Object propertyValue, Tag customTag) {
				// Don't write out null values
				if (propertyValue == null) {
					return null;
				}
				else {
					return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag);
				}
			}
		};
		representer.addClassTag(AntoraYml.class, Tag.MAP);
		DumperOptions ymlOptions = new DumperOptions();
		ymlOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
		ymlOptions.setDefaultScalarStyle(DumperOptions.ScalarStyle.SINGLE_QUOTED);
		return new Yaml(representer, ymlOptions);
	}

}
