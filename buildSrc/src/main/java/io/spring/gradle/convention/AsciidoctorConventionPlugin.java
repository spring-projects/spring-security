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

package io.spring.gradle.convention;

import org.asciidoctor.gradle.base.AsciidoctorAttributeProvider;
import org.asciidoctor.gradle.jvm.AbstractAsciidoctorTask;
import org.asciidoctor.gradle.jvm.AsciidoctorJExtension;
import org.asciidoctor.gradle.jvm.AsciidoctorJPlugin;
import org.asciidoctor.gradle.jvm.AsciidoctorTask;
import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.DependencySet;
import org.gradle.api.artifacts.dsl.RepositoryHandler;
import org.gradle.api.file.CopySpec;
import org.gradle.api.file.FileTree;
import org.gradle.api.tasks.Sync;

import java.io.File;
import java.net.URI;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/**
 * Conventions that are applied in the presence of the {@link AsciidoctorJPlugin}. When
 * the plugin is applied:
 *
 * <ul>
 * <li>All warnings are made fatal.
 * <li>A task is created to resolve and unzip our documentation resources (CSS and
 * Javascript).
 * <li>For each {@link AsciidoctorTask} (HTML only):
 * <ul>
 * <li>A configuration named asciidoctorExtensions is ued to add the
 * <a href="https://github.com/spring-io/spring-asciidoctor-extensions#block-switch">block
 * switch</a> extension
 * <li>{@code doctype} {@link AsciidoctorTask#options(Map) option} is configured.
 * <li>{@link AsciidoctorTask#attributes(Map) Attributes} are configured for syntax
 * highlighting, CSS styling, docinfo, etc.
 * </ul>
 * <li>For each {@link AbstractAsciidoctorTask} (HTML and PDF):
 * <ul>
 * <li>{@link AsciidoctorTask#attributes(Map) Attributes} are configured to enable
 * warnings for references to missing attributes, the year is added as @{code today-year},
 * etc
 * <li>{@link AbstractAsciidoctorTask#baseDirFollowsSourceDir() baseDirFollowsSourceDir()}
 * is enabled.
 * </ul>
 * </ul>
 *
 * @author Andy Wilkinson
 * @author Rob Winch
 */
public class AsciidoctorConventionPlugin implements Plugin<Project> {

	public void apply(Project project) {
		project.getPlugins().withType(AsciidoctorJPlugin.class, (asciidoctorPlugin) -> {
			createDefaultAsciidoctorRepository(project);
			makeAllWarningsFatal(project);
			Sync unzipResources = createUnzipDocumentationResourcesTask(project);
			project.getTasks().withType(AbstractAsciidoctorTask.class, (asciidoctorTask) -> {
				asciidoctorTask.dependsOn(unzipResources);
				configureExtensions(project, asciidoctorTask);
				configureCommonAttributes(project, asciidoctorTask);
				configureOptions(asciidoctorTask);
				asciidoctorTask.baseDirFollowsSourceDir();
				asciidoctorTask.useIntermediateWorkDir();
				asciidoctorTask.resources(new Action<CopySpec>() {
					@Override
					public void execute(CopySpec resourcesSpec) {
						resourcesSpec.from(unzipResources);
						resourcesSpec.from(asciidoctorTask.getSourceDir(), new Action<CopySpec>() {
							@Override
							public void execute(CopySpec resourcesSrcDirSpec) {
								// https://github.com/asciidoctor/asciidoctor-gradle-plugin/issues/523
								// For now copy the entire sourceDir over so that include files are
								// available in the intermediateWorkDir
								// resourcesSrcDirSpec.include("images/**");
							}
						});
					}
				});
				if (asciidoctorTask instanceof AsciidoctorTask) {
					configureHtmlOnlyAttributes(project, asciidoctorTask);
				}
			});
		});
	}

	private void createDefaultAsciidoctorRepository(Project project) {
		project.getGradle().afterProject(new Action<Project>() {
			@Override
			public void execute(Project project) {
				RepositoryHandler repositories = project.getRepositories();
				if (repositories.isEmpty()) {
					repositories.mavenCentral();
					repositories.maven(repo -> {
						repo.setUrl(URI.create("https://repo.spring.io/release"));
					});
				}
			}
		});
	}

	private void makeAllWarningsFatal(Project project) {
		project.getExtensions().getByType(AsciidoctorJExtension.class).fatalWarnings(".*");
	}

	private void configureExtensions(Project project, AbstractAsciidoctorTask asciidoctorTask) {
		Configuration extensionsConfiguration = project.getConfigurations().maybeCreate("asciidoctorExtensions");
		extensionsConfiguration.defaultDependencies(new Action<DependencySet>() {
			@Override
			public void execute(DependencySet dependencies) {
				dependencies.add(project.getDependencies().create("io.spring.asciidoctor:spring-asciidoctor-extensions-block-switch:0.4.2.RELEASE"));
			}
		});
		asciidoctorTask.configurations(extensionsConfiguration);
	}

	private Sync createUnzipDocumentationResourcesTask(Project project) {
		Configuration documentationResources = project.getConfigurations().maybeCreate("documentationResources");
		documentationResources.getDependencies()
				.add(project.getDependencies().create("io.spring.docresources:spring-doc-resources:0.2.1.RELEASE"));
		Sync unzipResources = project.getTasks().create("unzipDocumentationResources",
				Sync.class, new Action<Sync>() {
					@Override
			public void execute(Sync sync) {
				sync.dependsOn(documentationResources);
				sync.from(new Callable<List<FileTree>>() {
					@Override
					public List<FileTree> call() throws Exception {
						List<FileTree> result = new ArrayList<>();
						documentationResources.getAsFileTree().forEach(new Consumer<File>() {
							@Override
							public void accept(File file) {
								result.add(project.zipTree(file));
							}
						});
						return result;
					}
				});
				File destination = new File(project.getBuildDir(), "docs/resources");
				sync.into(project.relativePath(destination));
			}
		});
		return unzipResources;
	}

	private void configureOptions(AbstractAsciidoctorTask asciidoctorTask) {
		asciidoctorTask.options(Collections.singletonMap("doctype", "book"));
	}

	private void configureHtmlOnlyAttributes(Project project, AbstractAsciidoctorTask asciidoctorTask) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("source-highlighter", "highlight.js");
		attributes.put("highlightjsdir", "js/highlight");
		attributes.put("highlightjs-theme", "github");
		attributes.put("linkcss", true);
		attributes.put("icons", "font");
		attributes.put("stylesheet", "css/spring.css");
		asciidoctorTask.getAttributeProviders().add(new AsciidoctorAttributeProvider() {
			@Override
			public Map<String, Object> getAttributes() {
				Object version = project.getVersion();
				Map<String, Object> attrs = new HashMap<>();
				if (version != null && version.toString() != Project.DEFAULT_VERSION) {
					attrs.put("revnumber", version);
				}
				return attrs;
			}
		});
		asciidoctorTask.attributes(attributes);
	}

	private void configureCommonAttributes(Project project, AbstractAsciidoctorTask asciidoctorTask) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("attribute-missing", "warn");
		attributes.put("icons", "font");
		attributes.put("idprefix", "");
		attributes.put("idseparator", "-");
		attributes.put("docinfo", "shared");
		attributes.put("sectanchors", "");
		attributes.put("sectnums", "");
		attributes.put("today-year", LocalDate.now().getYear());
		asciidoctorTask.attributes(attributes);
	}
}
