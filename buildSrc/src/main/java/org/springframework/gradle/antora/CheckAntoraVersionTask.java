package org.springframework.gradle.antora;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
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
		String expectedAntoraDisplayVersion = getAntoraDisplayVersion().getOrElse(null);

		Representer representer = new Representer();
		representer.getPropertyUtils().setSkipMissingProperties(true);

		Yaml yaml = new Yaml(new Constructor(AntoraYml.class), representer);
		AntoraYml antoraYml = yaml.load(new FileInputStream(antoraYmlFile));

		String actualAntoraPrerelease = antoraYml.getPrerelease();
		boolean preReleaseMatches = antoraYml.getPrerelease() == null && expectedAntoraPrerelease == null ||
				(actualAntoraPrerelease != null && actualAntoraPrerelease.equals(expectedAntoraPrerelease));
		String actualAntoraDisplayVersion = antoraYml.getDisplay_version();
		boolean displayVersionMatches = antoraYml.getDisplay_version() == null && expectedAntoraDisplayVersion == null ||
				(actualAntoraDisplayVersion != null && actualAntoraDisplayVersion.equals(expectedAntoraDisplayVersion));
		String actualAntoraVersion = antoraYml.getVersion();
		if (!preReleaseMatches ||
				!displayVersionMatches ||
				!expectedAntoraVersion.equals(actualAntoraVersion)) {
			throw new GradleException("The Gradle version of '" + getProject().getVersion() + "' should have version: '"
					+ expectedAntoraVersion + "' prerelease: '" + expectedAntoraPrerelease + "' display_version: '"
					+ expectedAntoraDisplayVersion + "' defined in " + antoraYmlFile + " but got version: '"
					+ actualAntoraVersion + "' prerelease: '" + actualAntoraPrerelease + "' display_version: '" + actualAntoraDisplayVersion + "'");
		}
	}

	@InputFile
	public abstract RegularFileProperty getAntoraYmlFile();

	@Input
	public abstract Property<String> getAntoraVersion();

	@Input
	@Optional
	public abstract Property<String> getAntoraPrerelease();

	@Input
	@Optional
	public abstract Property<String> getAntoraDisplayVersion();

	public static class AntoraYml {
		private String version;

		private String prerelease;

		private String display_version;

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

		public String getDisplay_version() {
			return display_version;
		}

		public void setDisplay_version(String display_version) {
			this.display_version = display_version;
		}
	}
}
