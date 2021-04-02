/*
 * Copyright 2002-2016 the original author or authors.
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

package io.spring.gradle.convention;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPluginConvention;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.javadoc.Javadoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Rob Winch
 */
public class JavadocApiPlugin implements Plugin<Project> {
	Logger logger = LoggerFactory.getLogger(getClass());
	Set<Pattern> excludes = Collections.singleton(Pattern.compile("test"));

	@Override
	public void apply(Project project) {
		logger.info("Applied");
		Project rootProject = project.getRootProject();


		//Task docs = project.getTasks().findByPath("docs") ?: project.getTasks().create("docs");
		Javadoc api = project.getTasks().create("api", Javadoc);

		api.setGroup("Documentation");
		api.setDescription("Generates aggregated Javadoc API documentation.");

		Set<Project> subprojects = rootProject.getSubprojects();
		for (Project subproject : subprojects) {
			addProject(api, subproject);
		}

		if (subprojects.isEmpty()) {
			addProject(api, project);
		}

		api.setMaxMemory("1024m");
		api.setDestinationDir(new File(project.getBuildDir(), "api"));

		project.getPluginManager().apply("io.spring.convention.javadoc-options");
	}

	public void setExcludes(String... excludes) {
		if(excludes == null) {
			this.excludes = Collections.emptySet();
		}
		this.excludes = new HashSet<Pattern>(excludes.length);
		for(String exclude : excludes) {
			this.excludes.add(Pattern.compile(exclude));
		}
	}

	private void addProject(final Javadoc api, final Project project) {
		for(Pattern exclude : excludes) {
			if(exclude.matcher(project.getName()).matches()) {
				logger.info("Skipping {} because it is excluded by {}", project, exclude);
				return;
			}
		}
		logger.info("Try add sources for {}", project);
		project.getPlugins().withType(SpringModulePlugin.class).all(new Action<SpringModulePlugin>() {
			@Override
			public void execute(SpringModulePlugin plugin) {
				logger.info("Added sources for {}", project);

				JavaPluginConvention java = project.getConvention().getPlugin(JavaPluginConvention.class);
				SourceSet mainSourceSet = java.getSourceSets().getByName("main");

				api.setSource(api.getSource().plus(mainSourceSet.getAllJava()));
				project.getTasks().withType(Javadoc.class).all(new Action<Javadoc>() {
					@Override
					public void execute(Javadoc projectJavadoc) {
						api.setClasspath(api.getClasspath().plus(projectJavadoc.getClasspath()));
					}
				});
			}
		});
	}
}

