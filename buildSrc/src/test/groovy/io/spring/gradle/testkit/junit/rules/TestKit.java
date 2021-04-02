/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.spring.gradle.testkit.junit.rules;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Enumeration;

import org.apache.commons.io.FileUtils;
import org.gradle.testkit.runner.GradleRunner;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public class TestKit implements TestRule {
	final TemporaryFolder testProjectDir = new TemporaryFolder();
	File buildDir;

	@Override
	public Statement apply(Statement base, Description description) {
		Statement wrapped = new Statement() {

			@Override
			public void evaluate() throws Throwable {
				try {
					buildDir = testProjectDir.newFolder();
				} catch(IOException e) {
					throw new RuntimeException(e);
				}
				base.evaluate();
			}
		};
		return testProjectDir.apply(wrapped, description);
	}

	public File getRootDir() {
		return buildDir;
	}

	public GradleRunner withProjectDir(File projectDir) throws IOException {
		FileUtils.copyDirectory(projectDir, buildDir);
		return GradleRunner.create()
			.withProjectDir(buildDir)
			.withPluginClasspath();
	}

	public GradleRunner withProjectResource(String projectResourceName) throws IOException, URISyntaxException {
		ClassLoader classLoader = getClass().getClassLoader();
		Enumeration<URL> resources = classLoader.getResources(projectResourceName);
		if(!resources.hasMoreElements()) {
			throw new IOException("Cannot find resource " + projectResourceName + " with " + classLoader);
		}
		URL resourceUrl = resources.nextElement();
		File projectDir = Paths.get(resourceUrl.toURI()).toFile();
		return withProjectDir(projectDir);
	}
}
