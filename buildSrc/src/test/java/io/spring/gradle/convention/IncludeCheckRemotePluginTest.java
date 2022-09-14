/*
 * Copyright 2002-2022 the original author or authors.
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import io.spring.gradle.IncludeRepoTask;
import org.apache.commons.io.FileUtils;
import org.gradle.api.Project;
import org.gradle.api.tasks.GradleBuild;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IncludeCheckRemotePluginTest {

	Project rootProject;

	@AfterEach
	public void cleanup() throws Exception {
		if (rootProject != null) {
			FileUtils.deleteDirectory(rootProject.getProjectDir());
		}
	}

	@Test
	void applyWhenExtensionPropertiesNoTasksThenCreateCheckRemoteTaskWithDefaultTask() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
				});

		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote.getTasks()).containsExactly("check");
	}

	@Test
	void applyWhenExtensionPropertiesTasksThenCreateCheckRemoteWithProvidedTasks() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
					includeCheckRemoteExtension.setProperty("tasks", Arrays.asList("clean", "build", "test"));
				});

		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote.getTasks()).containsExactly("clean", "build", "test");
	}

	@Test
	void applyWhenExtensionPropertiesInitScriptsThenCreateCheckRemoteWithProvidedTasks() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
					includeCheckRemoteExtension.setProperty("initScripts", Arrays.asList("spring-security-ci.gradle"));
				});

		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote.getStartParameter().getAllInitScripts()).extracting(File::getName).containsExactly("spring-security-ci.gradle");
	}

	@Test
	void applyWhenExtensionPropertiesBuildPropertiesThenCreateCheckRemoteWithProvidedTasks() {
		Map<String, String> projectProperties = new HashMap<>();
		projectProperties.put("localRepositoryPath", "~/local/repository");
		projectProperties.put("anotherProperty", "some_value");
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
					includeCheckRemoteExtension.setProperty("projectProperties", projectProperties);
				});

		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote.getStartParameter().getProjectProperties()).containsEntry("localRepositoryPath", "~/local/repository")
				.containsEntry("anotherProperty", "some_value");
	}

	@Test
	void applyWhenExtensionPropertiesThenRegisterIncludeRepoTaskWithExtensionProperties() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
				});

		IncludeRepoTask includeRepo = (IncludeRepoTask) this.rootProject.getTasks().named("includeRepo").get();
		assertThat(includeRepo).isNotNull();
		assertThat(includeRepo.getRepository().get()).isEqualTo("my-project/my-repository");
		assertThat(includeRepo.getRef().get()).isEqualTo("main");
	}

	@Test
	void applyWhenRegisterTasksThenCheckRemoteDirSameAsIncludeRepoOutputDir() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
				});
		IncludeRepoTask includeRepo = (IncludeRepoTask) this.rootProject.getTasks().named("includeRepo").get();
		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote.getDir()).isEqualTo(includeRepo.getOutputDirectory());
	}

	@Test
	void applyWhenNoExtensionPropertiesThenRegisterTasks() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		IncludeRepoTask includeRepo = (IncludeRepoTask) this.rootProject.getTasks().named("includeRepo").get();
		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(includeRepo).isNotNull();
		assertThat(checkRemote).isNotNull();
	}

	@Test
	void applyWhenNoBuildScanSpecifiedThenRegisterCheckRemoteTaskWithBuildScanFalse() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
				});

		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote).isNotNull();
		assertThat(checkRemote.getStartParameter().isBuildScan()).isFalse();
	}

	@Test
	void applyWhenBuildScanTrueThenRegisterCheckRemoteTaskWithBuildScanTrue() {
		this.rootProject = ProjectBuilder.builder().build();
		this.rootProject.getPluginManager().apply(IncludeCheckRemotePlugin.class);
		this.rootProject.getExtensions().configure(IncludeCheckRemotePlugin.IncludeCheckRemoteExtension.class,
				(includeCheckRemoteExtension) -> {
					includeCheckRemoteExtension.setProperty("repository", "my-project/my-repository");
					includeCheckRemoteExtension.setProperty("ref", "main");
					includeCheckRemoteExtension.setProperty("buildScan", true);
				});

		GradleBuild checkRemote = (GradleBuild) this.rootProject.getTasks().named("checkRemote").get();
		assertThat(checkRemote).isNotNull();
		assertThat(checkRemote.getStartParameter().isBuildScan()).isTrue();
	}

}
