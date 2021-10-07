package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.apache.commons.io.FileUtils;
import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class JavadocApiPluginITest {
	private TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

	@Test
    public void multiModuleApi() throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/javadocapi/multimodule/")
				.withArguments("api")
				.build();
		assertThat(result.task(":api").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
        File allClasses = new File(testKit.getRootDir(), "build/api/allclasses-noframe.html");
		File index = new File(testKit.getRootDir(), "build/api/allclasses-index.html");
		File listing = allClasses.exists() ? allClasses : index;
		String listingText = FileUtils.readFileToString(listing);
		assertThat(listingText).contains("sample/Api.html");
        assertThat(listingText).contains("sample/Impl.html");
		assertThat(listingText).doesNotContain("sample/Sample.html");
	}
}
