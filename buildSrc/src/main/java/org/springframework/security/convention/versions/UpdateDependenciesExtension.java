package org.springframework.security.convention.versions;

import com.github.benmanes.gradle.versions.updates.resolutionstrategy.ComponentSelectionWithCurrent;
import org.gradle.api.Action;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;

public class UpdateDependenciesExtension {
	private Supplier<List<File>> files;

	private UpdateMode updateMode = UpdateMode.COMMIT;

	private DependencyExcludes dependencyExcludes = new DependencyExcludes();

	private GitHub gitHub = new GitHub();

	public UpdateDependenciesExtension(Supplier<List<File>> files) {
		this.files = files;
	}

	public void setUpdateMode(UpdateMode updateMode) {
		this.updateMode = updateMode;
	}

	public UpdateMode getUpdateMode() {
		return updateMode;
	}

	GitHub getGitHub() {
		return this.gitHub;
	}

	DependencyExcludes getExcludes() {
		return dependencyExcludes;
	}

	Supplier<List<File>> getFiles() {
		return files;
	}

	public void setFiles(Supplier<List<File>> files) {
		this.files = files;
	}

	public void addFiles(Supplier<List<File>> files) {
		Supplier<List<File>> original = this.files;
		setFiles(() -> {
			List<File> result = new ArrayList<>(original.get());
			result.addAll(files.get());
			return result;
		});
	}

	public void dependencyExcludes(Action<DependencyExcludes> excludes) {
		excludes.execute(this.dependencyExcludes);
	}

	public void gitHub(Action<GitHub> gitHub) {
		gitHub.execute(this.gitHub);
	}

	public enum UpdateMode {
		COMMIT,
		GITHUB_ISSUE
	}

	public class GitHub {
		private String organization;

		private String repository;

		private String accessToken;

		private String milestone;

		public String getOrganization() {
			return organization;
		}

		public void setOrganization(String organization) {
			this.organization = organization;
		}

		public String getRepository() {
			return repository;
		}

		public void setRepository(String repository) {
			this.repository = repository;
		}

		public String getAccessToken() {
			return accessToken;
		}

		public void setAccessToken(String accessToken) {
			this.accessToken = accessToken;
		}

		public String getMilestone() {
			return milestone;
		}

		public void setMilestone(String milestone) {
			this.milestone = milestone;
		}
	}

	/**
	 * Consider creating some Predicates instead since they are composible
	 */
	public class DependencyExcludes {
		private List<Action<ComponentSelectionWithCurrent>> actions = new ArrayList<>();

		List<Action<ComponentSelectionWithCurrent>> getActions() {
			return actions;
		}

		public DependencyExcludes alphaBetaVersions() {
			this.actions.add(excludeVersionWithRegex("(?i).*?(alpha|beta).*", "an alpha or beta version"));
			return this;
		}

		public DependencyExcludes majorVersionBump() {
			this.actions.add((selection) -> {
				String currentVersion = selection.getCurrentVersion();
				int separator = currentVersion.indexOf(".");
				String major = separator > 0 ? currentVersion.substring(0, separator) : currentVersion;
				String candidateVersion = selection.getCandidate().getVersion();
				Pattern calVerPattern = Pattern.compile("\\d\\d\\d\\d.*");
				boolean isCalVer = calVerPattern.matcher(candidateVersion).matches();
				if (!isCalVer && !candidateVersion.startsWith(major)) {
					selection.reject("Cannot upgrade to new Major Version");
				}
			});
			return this;
		}

		public DependencyExcludes releaseCandidatesVersions() {
			this.actions.add(excludeVersionWithRegex("(?i).*?rc\\d+.*", "a release candidate version"));
			return this;
		}

		public DependencyExcludes milestoneVersions() {
			this.actions.add(excludeVersionWithRegex("(?i).*?m\\d+.*", "a milestone version"));
			return this;
		}

		public DependencyExcludes snapshotVersions() {
			this.actions.add(excludeVersionWithRegex(".*?-SNAPSHOT.*", "a SNAPSHOT version"));
			return this;
		}

		private Action<ComponentSelectionWithCurrent> excludeVersionWithRegex(String regex, String reason) {
			Pattern pattern = Pattern.compile(regex);
			return (selection) -> {
				String candidateVersion = selection.getCandidate().getVersion();
				if (pattern.matcher(candidateVersion).matches()) {
					selection.reject(candidateVersion + " is not allowed because it is " + reason);
				}
			};
		}
	}
}
