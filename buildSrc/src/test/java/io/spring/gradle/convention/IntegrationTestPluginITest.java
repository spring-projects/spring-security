package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrationTestPluginITest {
	private io.spring.gradle.TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

    @Test
	public void checkWithJavaPlugin() throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/integrationtest/withjava/")
				.withArguments("check")
				.build();
		assertThat(result.task(":check").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
		assertThat(new File(testKit.getRootDir(), "build/test-results/integrationTest/")).exists();
		assertThat(new File(testKit.getRootDir(), "build/reports/tests/integrationTest/")).exists();
	}

	@Test
    public void checkWithPropdeps() throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/integrationtest/withpropdeps/")
				.withArguments("check")
				.build();
		assertThat(result.task(":check").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
		assertThat(new File(testKit.getRootDir(), "build/test-results/integrationTest/")).exists();
		assertThat(new File(testKit.getRootDir(), "build/reports/tests/integrationTest/")).exists();
	}

	@Test
    public void checkWithGroovy() throws Exception {
		BuildResult result = this.testKit.withProjectResource("samples/integrationtest/withgroovy/")
				.withArguments("check")
				.build();
		assertThat(result.task(":check").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
		assertThat(new File(testKit.getRootDir(), "build/test-results/integrationTest/")).exists();
		assertThat(new File(testKit.getRootDir(), "build/reports/tests/integrationTest/")).exists();
	}
}
