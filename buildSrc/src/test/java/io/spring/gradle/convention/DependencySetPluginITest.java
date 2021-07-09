package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.gradle.testkit.runner.BuildResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.gradle.testkit.runner.TaskOutcome.SUCCESS;

public class DependencySetPluginITest {
	private TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

	@Test
	public void dependencies() throws Exception {
		BuildResult result = testKit.withProjectResource("samples/dependencyset")
				.withArguments("dependencies")
				.build();

		assertThat(result.task(":dependencies").getOutcome()).isEqualTo(SUCCESS);
		assertThat(result.getOutput()).doesNotContain("FAILED");
	}
}
