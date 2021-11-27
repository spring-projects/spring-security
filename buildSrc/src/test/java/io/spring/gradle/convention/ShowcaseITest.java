package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class ShowcaseITest {
	private TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

    @Test
	public void build() throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/showcase/")
				.withArguments("build", "--stacktrace")
				.forwardOutput()
				.build();
		assertThat(result.getOutput()).contains("BUILD SUCCESSFUL");
	}

	@Test
	@Disabled
    public void install() throws Exception {
		BuildResult result = this.testKit
			.withProjectResource("samples/showcase/")
			.withArguments("install", "--stacktrace")
			.build();

        assertThat(result.getOutput()).contains("SUCCESS");

		File pom = new File(testKit.getRootDir(), "sgbcs-core/build/poms/pom-default.xml");
		assertThat(pom).exists();

		String pomText = new String(Files.readAllBytes(pom.toPath()));
		String pomTextNoSpace = pomText.replaceAll("\\s", "");

		assertThat(pomText).doesNotContain("<dependencyManagement>");

		assertThat(pomTextNoSpace).contains("<dependency>\n			<groupId>org.springframework</groupId>\n			<artifactId>spring-test</artifactId>\n			<scope>test</scope>\n			<version>4.3.6.RELEASE</version>\n		</dependency>".replaceAll("\\s", ""));
		assertThat(pomTextNoSpace).contains("<developers>\n			<developer>\n				<id>rwinch</id>\n				<name>Rob Winch</name>\n				<email>rwinch@pivotal.io</email>\n			</developer>\n			<developer>\n				<id>jgrandja</id>\n				<name>Joe Grandja</name>\n				<email>jgrandja@pivotal.io</email>\n			</developer>\n		</developers>".replaceAll("\\s", ""));
		assertThat(pomTextNoSpace).contains("<scm>\n			<connection>scm:git:git://github.com/spring-projects/spring-security</connection>\n			<developerConnection>scm:git:git://github.com/spring-projects/spring-security</developerConnection>\n			<url>https://github.com/spring-projects/spring-security</url>\n		</scm>".replaceAll("\\s", ""));
		assertThat(pomTextNoSpace).contains("<description>sgbcs-core</description>");
		assertThat(pomTextNoSpace).contains("<url>https://spring.io/spring-security</url>");
		assertThat(pomTextNoSpace).contains("<organization>\n			<name>spring.io</name>\n			<url>https://spring.io/</url>\n		</organization>".replaceAll("\\s", ""));
		assertThat(pomTextNoSpace).contains("	<licenses>\n			<license>\n				<name>The Apache Software License, Version 2.0</name>\n				<url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>\n				<distribution>repo</distribution>\n			</license>\n		</licenses>".replaceAll("\\s", ""));
		assertThat(pomTextNoSpace).contains("<scm>\n			<connection>scm:git:git://github.com/spring-projects/spring-security</connection>\n			<developerConnection>scm:git:git://github.com/spring-projects/spring-security</developerConnection>\n			<url>https://github.com/spring-projects/spring-security</url>\n		</scm>".replaceAll("\\s", ""));

		File bom = new File(testKit.getRootDir(), "bom/build/poms/pom-default.xml");
		assertThat(bom).exists();
		assertThat(bom).hasContent("<artifactId>sgbcs-core</artifactId>");

		BuildResult secondBuild = this.testKit.withProjectResource("samples/showcase/").withArguments("mavenBom", "--stacktrace").build();
		// mavenBom is not up to date since install is never up to date
		assertThat(result.task(":bom:mavenBom").getOutcome()).isEqualTo(TaskOutcome.SUCCESS);
	}

}
