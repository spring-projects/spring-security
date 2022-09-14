package org.springframework.gradle.antora;

import org.apache.commons.io.IOUtils;
import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIOException;

class AntoraVersionPluginTests {

	@Test
	void defaultsPropertiesWhenSnapshot() {
		String expectedVersion = "1.0.0-SNAPSHOT";
		Project project = ProjectBuilder.builder().build();
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThat(checkAntoraVersionTask.getAntoraVersion().get()).isEqualTo("1.0.0");
		assertThat(checkAntoraVersionTask.getAntoraPrerelease().get()).isEqualTo("-SNAPSHOT");
		assertThat(checkAntoraVersionTask.getAntoraDisplayVersion().isPresent()).isFalse();
		assertThat(checkAntoraVersionTask.getAntoraYmlFile().getAsFile().get()).isEqualTo(project.file("antora.yml"));
	}

	@Test
	void defaultsPropertiesWhenMilestone() {
		String expectedVersion = "1.0.0-M1";
		Project project = ProjectBuilder.builder().build();
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThat(checkAntoraVersionTask.getAntoraVersion().get()).isEqualTo("1.0.0-M1");
		assertThat(checkAntoraVersionTask.getAntoraPrerelease().get()).isEqualTo("true");
		assertThat(checkAntoraVersionTask.getAntoraDisplayVersion().get()).isEqualTo(checkAntoraVersionTask.getAntoraVersion().get());
		assertThat(checkAntoraVersionTask.getAntoraYmlFile().getAsFile().get()).isEqualTo(project.file("antora.yml"));
	}

	@Test
	void defaultsPropertiesWhenRc() {
		String expectedVersion = "1.0.0-RC1";
		Project project = ProjectBuilder.builder().build();
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThat(checkAntoraVersionTask.getAntoraVersion().get()).isEqualTo("1.0.0-RC1");
		assertThat(checkAntoraVersionTask.getAntoraPrerelease().get()).isEqualTo("true");
		assertThat(checkAntoraVersionTask.getAntoraDisplayVersion().get()).isEqualTo(checkAntoraVersionTask.getAntoraVersion().get());
		assertThat(checkAntoraVersionTask.getAntoraYmlFile().getAsFile().get()).isEqualTo(project.file("antora.yml"));
	}

	@Test
	void defaultsPropertiesWhenRelease() {
		String expectedVersion = "1.0.0";
		Project project = ProjectBuilder.builder().build();
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThat(checkAntoraVersionTask.getAntoraVersion().get()).isEqualTo("1.0.0");
		assertThat(checkAntoraVersionTask.getAntoraPrerelease().isPresent()).isFalse();
		assertThat(checkAntoraVersionTask.getAntoraDisplayVersion().isPresent()).isFalse();
		assertThat(checkAntoraVersionTask.getAntoraYmlFile().getAsFile().get()).isEqualTo(project.file("antora.yml"));
	}

	@Test
	void explicitProperties() {
		Project project = ProjectBuilder.builder().build();
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		checkAntoraVersionTask.getAntoraVersion().set("1.0.0");
		checkAntoraVersionTask.getAntoraPrerelease().set("-SNAPSHOT");
		assertThat(checkAntoraVersionTask.getAntoraVersion().get()).isEqualTo("1.0.0");
		assertThat(checkAntoraVersionTask.getAntoraPrerelease().get()).isEqualTo("-SNAPSHOT");
		assertThat(checkAntoraVersionTask.getAntoraDisplayVersion().isPresent()).isFalse();
		assertThat(checkAntoraVersionTask.getAntoraYmlFile().getAsFile().get()).isEqualTo(project.file("antora.yml"));
	}

	@Test
	void versionNotDefined() throws Exception {
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThatExceptionOfType(GradleException.class).isThrownBy(() -> checkAntoraVersionTask.check());
	}

	@Test
	void antoraFileNotFound() throws Exception {
		String expectedVersion = "1.0.0-SNAPSHOT";
		Project project = ProjectBuilder.builder().build();
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThatIOException().isThrownBy(() -> checkAntoraVersionTask.check());
	}

	@Test
	void actualAntoraPrereleaseNull() throws Exception {
		String expectedVersion = "1.0.0-SNAPSHOT";
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		assertThatExceptionOfType(GradleException.class).isThrownBy(() -> checkAntoraVersionTask.check());

	}

	@Test
	void matchesWhenSnapshot() throws Exception {
		String expectedVersion = "1.0.0-SNAPSHOT";
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0'\nprerelease: '-SNAPSHOT'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		checkAntoraVersionTask.check();
	}

	@Test
	void matchesWhenMilestone() throws Exception {
		String expectedVersion = "1.0.0-M1";
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0-M1'\nprerelease: 'true'\ndisplay_version: '1.0.0-M1'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		checkAntoraVersionTask.check();
	}

	@Test
	void matchesWhenRc() throws Exception {
		String expectedVersion = "1.0.0-RC1";
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0-RC1'\nprerelease: 'true'\ndisplay_version: '1.0.0-RC1'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		checkAntoraVersionTask.check();
	}

	@Test
	void matchesWhenReleaseAndPrereleaseUndefined() throws Exception {
		String expectedVersion = "1.0.0";
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.setVersion(expectedVersion);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);

		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		checkAntoraVersionTask.check();
	}

	@Test
	void matchesWhenExplicitRelease() throws Exception {
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);
		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		((CheckAntoraVersionTask) task).getAntoraVersion().set("1.0.0");
		checkAntoraVersionTask.check();
	}

	@Test
	void matchesWhenExplicitPrerelease() throws Exception {
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("version: '1.0.0'\nprerelease: '-SNAPSHOT'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);
		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		((CheckAntoraVersionTask) task).getAntoraVersion().set("1.0.0");
		((CheckAntoraVersionTask) task).getAntoraPrerelease().set("-SNAPSHOT");
		checkAntoraVersionTask.check();
	}

	@Test
	void matchesWhenMissingPropertyDefined() throws Exception {
		Project project = ProjectBuilder.builder().build();
		File rootDir = project.getRootDir();
		IOUtils.write("name: 'ROOT'\nversion: '1.0.0'", new FileOutputStream(new File(rootDir, "antora.yml")), StandardCharsets.UTF_8);
		project.getPluginManager().apply(AntoraVersionPlugin.class);

		Task task = project.getTasks().findByName(AntoraVersionPlugin.ANTORA_CHECK_VERSION_TASK_NAME);

		assertThat(task).isInstanceOf(CheckAntoraVersionTask.class);
		CheckAntoraVersionTask checkAntoraVersionTask = (CheckAntoraVersionTask) task;
		((CheckAntoraVersionTask) task).getAntoraVersion().set("1.0.0");
		checkAntoraVersionTask.check();
	}

}
