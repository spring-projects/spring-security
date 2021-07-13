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
}
