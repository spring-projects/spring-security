/*
 * Copyright 2019-2023 the original author or authors.
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

package org.springframework.gradle.xsd;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.*;
import org.gradle.work.DisableCachingByDefault;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Creates the spring-security.xsd automatically
 *
 * @author Rob Winch
 */
@DisableCachingByDefault(because = "not worth it")
public abstract class CreateVersionlessXsdTask extends DefaultTask {

	@InputFiles
	public abstract ConfigurableFileCollection getInputFiles();

	@OutputFile
	abstract RegularFileProperty getVersionlessXsdFile();

	@TaskAction
	void createVersionlessXsd() throws IOException {
		XsdFileMajorMinorVersion largest = null;
		ConfigurableFileCollection inputFiles = getInputFiles();
		if (inputFiles.isEmpty()) {
			throw new IllegalStateException("No Inputs configured");
		}
		for (File file : inputFiles) {
			XsdFileMajorMinorVersion current = XsdFileMajorMinorVersion.create(file);
			if (current == null) {
				continue;
			}
			if (largest == null) {
				largest = current;
			}
			else if (current.getVersion().isGreaterThan(largest.getVersion())) {
				largest = current;
			}
		}
		if (largest == null) {
			throw new IllegalStateException("Could not create versionless xsd file because no files matching spring-security-<digit>.xsd were found in " + inputFiles.getFiles());
		}
		Path to = getVersionlessXsdFile().getAsFile().get().toPath();
		Path from = largest.getFile().toPath();
		Files.copy(from, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
	}

	static class XsdFileMajorMinorVersion {
		private final File file;

		private final MajorMinorVersion version;

		private XsdFileMajorMinorVersion(File file, MajorMinorVersion version) {
			this.file = file;
			this.version = version;
		}

		private static final Pattern FILE_MAJOR_MINOR_VERSION_PATTERN = Pattern.compile("^spring-security-(\\d+)\\.(\\d+)\\.xsd$");

		/**
		 * If matches xsd with major minor version (e.g. spring-security-5.1.xsd returns it, otherwise null
		 * @param file
		 * @return
		 */
		static XsdFileMajorMinorVersion create(File file) {
			String fileName = file.getName();
			Matcher matcher = FILE_MAJOR_MINOR_VERSION_PATTERN.matcher(fileName);
			if (!matcher.find()) {
				return null;
			}
			int major = Integer.parseInt(matcher.group(1));
			int minor = Integer.parseInt(matcher.group(2));
			MajorMinorVersion version = new MajorMinorVersion(major, minor);
			return new XsdFileMajorMinorVersion(file, version);
		}

		public File getFile() {
			return file;
		}

		public MajorMinorVersion getVersion() {
			return version;
		}
	}

	static class MajorMinorVersion {
		private final int major;

		private final int minor;

		MajorMinorVersion(int major, int minor) {
			this.major = major;
			this.minor = minor;
		}

		public int getMajor() {
			return major;
		}

		public int getMinor() {
			return minor;
		}

		public boolean isGreaterThan(MajorMinorVersion version) {
			if (getMajor() > version.getMajor()) {
				return true;
			}
			if (getMajor() < version.getMajor()) {
				return false;
			}
			if (getMinor() > version.getMinor()) {
				return true;
			}
			if (getMinor() < version.getMinor()) {
				return false;
			}
			// they are equal
			return false;
		}
	}
}
