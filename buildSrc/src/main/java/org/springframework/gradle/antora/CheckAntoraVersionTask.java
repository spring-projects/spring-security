package org.springframework.gradle.antora;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.TaskAction;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

public abstract class CheckAntoraVersionTask extends DefaultTask {

	@TaskAction
	public void check() throws FileNotFoundException {
		File antoraYmlFile = getAntoraYmlFile().getAsFile().get();
		String expectedAntoraVersion = getAntoraVersion().get();
		String expectedAntoraPrerelease = getAntoraPrerelease().getOrElse(null);

		Representer representer = new Representer();
		representer.getPropertyUtils().setSkipMissingProperties(true);

		Yaml yaml = new Yaml(new Constructor(AntoraYml.class), representer);
		AntoraYml antoraYml = yaml.load(new FileInputStream(antoraYmlFile));

		String actualAntoraPrerelease = antoraYml.getPrerelease();
		boolean preReleaseMatches = antoraYml.getPrerelease() == null && expectedAntoraPrerelease == null ||
				(actualAntoraPrerelease != null && actualAntoraPrerelease.equals(expectedAntoraPrerelease));
		String actualAntoraVersion = antoraYml.getVersion();
		if (!preReleaseMatches ||
				!expectedAntoraVersion.equals(actualAntoraVersion)) {
			throw new GradleException("The Gradle version of '" + getProject().getVersion() + "' should have version: '" + expectedAntoraVersion + "' and prerelease: '" + expectedAntoraPrerelease + "' defined in " + antoraYmlFile + " but got version: '" + actualAntoraVersion+"' and prerelease: '" + actualAntoraPrerelease + "'");
		}
	}

	@InputFile
	public abstract RegularFileProperty getAntoraYmlFile();

	@Input
	public abstract Property<String> getAntoraVersion();

	@Input
	public abstract Property<String> getAntoraPrerelease();

	public static class AntoraYml {
		private String version;

		private String prerelease;

		public String getVersion() {
			return version;
		}

		public void setVersion(String version) {
			this.version = version;
		}

		public String getPrerelease() {
			return prerelease;
		}

		public void setPrerelease(String prerelease) {
			this.prerelease = prerelease;
		}
	}
}
