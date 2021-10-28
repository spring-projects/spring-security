/*
 * Copyright 2002-2021 the original author or authors.
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

package s101;

import java.io.File;

import org.gradle.api.Project;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;

public class S101PluginExtension {
	private final Property<String> licenseId;
	private final Property<File> installationDirectory;
	private final Property<File> configurationDirectory;
	private final Property<String> label;

	@Input
	public Property<String> getLicenseId() {
		return this.licenseId;
	}

	public void setLicenseId(String licenseId) {
		this.licenseId.set(licenseId);
	}

	@InputDirectory
	public Property<File> getInstallationDirectory() {
		return this.installationDirectory;
	}

	public void setInstallationDirectory(String installationDirectory) {
		this.installationDirectory.set(new File(installationDirectory));
	}

	@InputDirectory
	public Property<File> getConfigurationDirectory() {
		return this.configurationDirectory;
	}

	public void setConfigurationDirectory(String configurationDirectory) {
		this.configurationDirectory.set(new File(configurationDirectory));
	}

	@Input
	public Property<String> getLabel() {
		return this.label;
	}

	public void setLabel(String label) {
		this.label.set(label);
	}

	public S101PluginExtension(Project project) {
		this.licenseId = project.getObjects().property(String.class);
		if (project.hasProperty("s101.licenseId")) {
			setLicenseId((String) project.findProperty("s101.licenseId"));
		}
		this.installationDirectory = project.getObjects().property(File.class)
				.convention(new File(project.getBuildDir(), "s101"));
		this.configurationDirectory = project.getObjects().property(File.class)
				.convention(new File(project.getProjectDir(), "s101"));
		this.label = project.getObjects().property(String.class);
		if (project.hasProperty("s101.label")) {
			setLabel((String) project.findProperty("s101.label"));
		}
	}
}
