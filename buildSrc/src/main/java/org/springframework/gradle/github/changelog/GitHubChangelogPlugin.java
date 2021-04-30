/*
 * Copyright 2019-2020 the original author or authors.
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

package org.springframework.gradle.github.changelog;

import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.DependencySet;
import org.gradle.api.artifacts.repositories.ExclusiveContentRepository;
import org.gradle.api.artifacts.repositories.InclusiveRepositoryContentDescriptor;
import org.gradle.api.artifacts.repositories.IvyArtifactRepository;
import org.gradle.api.artifacts.repositories.IvyPatternRepositoryLayout;
import org.gradle.api.tasks.JavaExec;

import java.io.File;
import java.nio.file.Paths;

public class GitHubChangelogPlugin implements Plugin<Project> {

	public static final String CHANGELOG_GENERATOR_CONFIGURATION_NAME = "changelogGenerator";

	@Override
	public void apply(Project project) {
		createRepository(project);
		createChangelogGeneratorConfiguration(project);
		project.getTasks().register("generateChangelog", JavaExec.class, new Action<JavaExec>() {
			@Override
			public void execute(JavaExec generateChangelog) {
				File outputFile = project.file(Paths.get(project.getBuildDir().getPath(), "changelog/release-notes.md"));
				outputFile.getParentFile().mkdirs();
				generateChangelog.setGroup("Release");
				generateChangelog.setDescription("Generates the changelog");
				generateChangelog.setWorkingDir(project.getRootDir());
				generateChangelog.classpath(project.getConfigurations().getAt(CHANGELOG_GENERATOR_CONFIGURATION_NAME));
				generateChangelog.doFirst(new Action<Task>() {
					@Override
					public void execute(Task task) {
						generateChangelog.args("--spring.config.location=scripts/release/release-notes-sections.yml", project.property("nextVersion"), outputFile.toString());
					}
				});
			}
		});
	}

	private void createChangelogGeneratorConfiguration(Project project) {
		project.getConfigurations().create(CHANGELOG_GENERATOR_CONFIGURATION_NAME, new Action<Configuration>() {
			@Override
			public void execute(Configuration configuration) {
				configuration.defaultDependencies(new Action<DependencySet>() {
					@Override
					public void execute(DependencySet dependencies) {
						dependencies.add(project.getDependencies().create("spring-io:github-changelog-generator:0.0.6"));
					}
				});
			}
		});
	}

	private void createRepository(Project project) {
		IvyArtifactRepository repository = project.getRepositories().ivy(new Action<IvyArtifactRepository>() {
			@Override
			public void execute(IvyArtifactRepository repository) {
				repository.setUrl("https://github.com/");
				repository.patternLayout(new Action<IvyPatternRepositoryLayout>() {
					@Override
					public void execute(IvyPatternRepositoryLayout layout) {
						layout.artifact("[organization]/[artifact]/releases/download/v[revision]/[artifact].[ext]");
					}
				});
				repository.getMetadataSources().artifact();
			}
		});
		project.getRepositories().exclusiveContent(new Action<ExclusiveContentRepository>() {
			@Override
			public void execute(ExclusiveContentRepository exclusiveContentRepository) {
				exclusiveContentRepository.forRepositories(repository);
				exclusiveContentRepository.filter(new Action<InclusiveRepositoryContentDescriptor>() {
					@Override
					public void execute(InclusiveRepositoryContentDescriptor descriptor) {
						descriptor.includeGroup("spring-io");
					}
				});
			}
		});
	}
}
