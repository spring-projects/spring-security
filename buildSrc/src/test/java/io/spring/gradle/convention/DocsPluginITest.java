package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.codehaus.groovy.runtime.ResourceGroovyMethods;
import org.gradle.testkit.runner.BuildResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.gradle.testkit.runner.TaskOutcome.FAILED;
import static org.gradle.testkit.runner.TaskOutcome.SUCCESS;

public class DocsPluginITest {
	private TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

	@Test
	public void buildTriggersDocs() throws Exception {
		BuildResult result = testKit.withProjectResource("samples/docs/simple/")
				.withArguments("build")
				.build();
		assertThat(result.task(":build").getOutcome()).isEqualTo(SUCCESS);
		assertThat(result.task(":docs").getOutcome()).isEqualTo(SUCCESS);
		assertThat(result.task(":docsZip").getOutcome()).isEqualTo(SUCCESS);
		File zip = new File(testKit.getRootDir(), "build/distributions/simple-1.0.0.BUILD-SNAPSHOT-docs.zip");
		try (ZipFile file = new ZipFile(zip)) {
			List<? extends ZipEntry> entries = Collections.list(file.entries());
			assertThat(entries)
					.extracting(ZipEntry::getName)
					.contains("docs/reference/html5/index.html")
					.contains("docs/reference/pdf/simple-reference.pdf");
		}
	}

	@Test
	public void asciidocCopiesImages() throws Exception {
		BuildResult result = testKit.withProjectResource("samples/docs/simple/").withArguments("asciidoctor").build();
		assertThat(result.task(":asciidoctor").getOutcome()).isEqualTo(SUCCESS);
		assertThat(new File(testKit.getRootDir(), "build/docs/asciidoc/images")).exists();
	}

	@Test
	public void asciidocDocInfoFromResourcesUsed() throws Exception {
		BuildResult result = this.testKit.withProjectResource("samples/docs/simple/")
				.withArguments("asciidoctor")
				.build();
		assertThat(result.task(":asciidoctor").getOutcome()).isEqualTo(SUCCESS);
		assertThat(ResourceGroovyMethods.getText(new File(testKit.getRootDir(), "build/docs/asciidoc/index.html")))
				.contains("<script type=\"text/javascript\" src=\"js/tocbot/tocbot.min.js\"></script>");
	}

	@Test
	public void missingAttributeFails() throws Exception {
		BuildResult result = this.testKit.withProjectResource("samples/docs/missing-attribute/")
				.withArguments(":asciidoctor")
				.buildAndFail();
		assertThat(result.task(":asciidoctor").getOutcome()).isEqualTo(FAILED);
	}

	@Test
	public void missingInclude() throws Exception {
		BuildResult result = this.testKit.withProjectResource("samples/docs/missing-include/")
				.withArguments(":asciidoctor")
				.buildAndFail();
		assertThat(result.task(":asciidoctor").getOutcome()).isEqualTo(FAILED);
	}

	@Test
	public void missingCrossReference() throws Exception {
		BuildResult result = this.testKit.withProjectResource("samples/docs/missing-cross-reference/")
				.withArguments(":asciidoctor")
				.buildAndFail();
		assertThat(result.task(":asciidoctor").getOutcome()).isEqualTo(FAILED);
	}
}
