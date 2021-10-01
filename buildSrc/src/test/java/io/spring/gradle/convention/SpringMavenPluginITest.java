package io.spring.gradle.convention;

import io.spring.gradle.TestKit;
import org.apache.commons.io.IOUtils;
import org.gradle.testkit.runner.BuildResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class SpringMavenPluginITest {

	private TestKit testKit;

	@BeforeEach
	void setup(@TempDir Path tempDir) {
		this.testKit = new TestKit(tempDir.toFile());
	}

    @Disabled
	@Test
    public void install()  throws Exception {
        BuildResult result = this.testKit.withProjectResource("samples/maven/install")
				.withArguments("install")
				.build();
		assertThat(result.getOutput()).contains("SUCCESS");
		File pom = new File(testKit.getRootDir(), "build/poms/pom-default.xml");
		assertThat(pom).exists();
		String pomText = new String(Files.readAllBytes(pom.toPath()));
		assertThat(pomText.replaceAll("\\s", "")).contains("<dependency>\n			<groupId>aopalliance</groupId>\n			<artifactId>aopalliance</artifactId>\n			<version>1.0</version>\n			<scope>compile</scope>\n			<optional>true</optional>\n		</dependency>".replaceAll("\\s", ""));
	}

    @Disabled
	@Test
    public void signArchivesWhenInMemory() throws Exception {
        LinkedHashMap<String, String> map = new LinkedHashMap<String, String>(2);
        map.put("ORG_GRADLE_PROJECT_signingKey", getSigningKey());
        map.put("ORG_GRADLE_PROJECT_signingPassword", "password");
        BuildResult result = this.testKit.withProjectResource("samples/maven/signing")
				.withArguments("signArchives")
				.withEnvironment(map)
				.forwardOutput()
				.build();
		assertThat(result.getOutput()).contains("SUCCESS");
		final File jar = new File(testKit.getRootDir(), "build/libs/signing-1.0.0.RELEASE.jar");
		assertThat(jar).exists();
		File signature = new File(jar.getAbsolutePath() + ".asc");
		assertThat(signature).exists();
	}

    public String getSigningKey() throws Exception {
		return IOUtils.toString(getClass().getResource("/test-private.pgp"));
	}
}
