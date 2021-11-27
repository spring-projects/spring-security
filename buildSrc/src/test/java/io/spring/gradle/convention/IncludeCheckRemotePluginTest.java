/*
 * Copyright 2002-2021 the original author or authors.
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

import io.spring.gradle.IncludeRepoTask;
import org.apache.commons.io.FileUtils;
import org.gradle.api.Project;
import org.gradle.api.tasks.GradleBuild;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

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

}
