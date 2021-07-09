package io.spring.gradle.convention;

import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class JacocoPluginITest{
	private io.spring.gradle.TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new io.spring.gradle.TestKit(tempDir.toFile());
	}

    @Test
	public void checkWithJavaPlugin() throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/jacoco/java/")
				.withArguments("check")
				.build();
		assertThat(result.task(":check").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
		assertThat(new File(testKit.getRootDir(), "build/jacoco")).exists();
		assertThat(new File(testKit.getRootDir(), "build/reports/jacoco/test/html/")).exists();
	}
}
