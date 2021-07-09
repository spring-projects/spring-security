package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class TestsConfigurationPluginITest {

	private TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

	@Test
    public void canFindDepencency() throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/testsconfiguration")
				.withArguments("check")
				.build();
		assertThat(result.task(":web:check").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
	}

}
