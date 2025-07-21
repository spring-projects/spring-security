/*
 * Copyright 2012-2022 the original author or authors.
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

package org.springframework.gradle.classpath;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.Task;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.ModuleVersionIdentifier;
import org.gradle.api.artifacts.ResolvedConfiguration;
import org.gradle.api.file.FileCollection;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.TaskAction;

import java.io.IOException;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * A {@link Task} for checking the classpath for prohibited dependencies.
 *
 * @author Andy Wilkinson
 */
public class CheckClasspathForProhibitedDependencies extends DefaultTask {

	private Configuration classpath;

	public CheckClasspathForProhibitedDependencies() {
		getOutputs().upToDateWhen((task) -> true);
	}

	public void setClasspath(Configuration classpath) {
		this.classpath = classpath;
	}

	@Classpath
	public FileCollection getClasspath() {
		return this.classpath;
	}

	@TaskAction
	public void checkForProhibitedDependencies() throws IOException {
		ResolvedConfiguration resolvedConfiguration = this.classpath.getResolvedConfiguration();
		TreeSet<String> prohibited = resolvedConfiguration.getResolvedArtifacts().stream()
				.map((artifact) -> artifact.getModuleVersion().getId()).filter(this::prohibited)
				.map((id) -> id.getGroup() + ":" + id.getName()).collect(Collectors.toCollection(TreeSet::new));
		if (!prohibited.isEmpty()) {
			StringBuilder message = new StringBuilder(String.format("Found prohibited dependencies in '%s':%n", this.classpath.getName()));
			for (String dependency : prohibited) {
				message.append(String.format("    %s%n", dependency));
			}
			throw new GradleException(message.toString());
		}
	}

	private boolean prohibited(ModuleVersionIdentifier id) {
		String group = id.getGroup();
		if (group.equals("javax.batch")) {
			return false;
		}
		if (group.equals("javax.cache")) {
			return false;
		}
		if (group.equals("javax.money")) {
			return false;
		}
		if (group.startsWith("javax")) {
			return true;
		}
		if (group.equals("org.slf4j") && id.getName().equals("jcl-over-slf4j")) {
			return true;
		}
		if (group.startsWith("org.jboss.spec")) {
			return true;
		}
		if (group.equals("org.apache.geronimo.specs")) {
			return true;
		}
		return false;
	}

}
