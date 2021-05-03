/*
 * Copyright 2019-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.convention.versions;

import com.github.benmanes.gradle.versions.reporter.result.Dependency;
import com.github.benmanes.gradle.versions.reporter.result.DependencyOutdated;
import com.github.benmanes.gradle.versions.reporter.result.Result;
import com.github.benmanes.gradle.versions.reporter.result.VersionAvailable;
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask;
import com.github.benmanes.gradle.versions.updates.gradle.GradleUpdateResult;
import com.github.benmanes.gradle.versions.updates.resolutionstrategy.ComponentSelectionRulesWithCurrent;
import com.github.benmanes.gradle.versions.updates.resolutionstrategy.ComponentSelectionWithCurrent;
import com.github.benmanes.gradle.versions.updates.resolutionstrategy.ResolutionStrategyWithCurrent;
import groovy.lang.Closure;
import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.component.ModuleComponentIdentifier;
import reactor.core.publisher.Mono;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.convention.versions.TransitiveDependencyLookupUtils.NIMBUS_JOSE_JWT_NAME;
import static org.springframework.security.convention.versions.TransitiveDependencyLookupUtils.OIDC_SDK_NAME;

public class UpdateDependenciesPlugin implements Plugin<Project> {
	private GitHubApi gitHubApi;

	@Override
	public void apply(Project project) {
		UpdateDependenciesExtension updateDependenciesSettings = project.getExtensions().create("updateDependenciesSettings", UpdateDependenciesExtension.class, defaultFiles(project));
		if (project.hasProperty("updateMode")) {
			String updateMode = String.valueOf(project.findProperty("updateMode"));
			updateDependenciesSettings.setUpdateMode(UpdateDependenciesExtension.UpdateMode.valueOf(updateMode));
		}
		if (project.hasProperty("nextVersion")) {
			String nextVersion = String.valueOf(project.findProperty("nextVersion"));
			updateDependenciesSettings.getGitHub().setMilestone(nextVersion);
		}
		if (project.hasProperty("gitHubAccessToken")) {
			String gitHubAccessToken = String.valueOf(project.findProperty("gitHubAccessToken"));
			updateDependenciesSettings.getGitHub().setAccessToken(gitHubAccessToken);
		}
		project.getTasks().register("updateDependencies", DependencyUpdatesTask.class, new Action<DependencyUpdatesTask>() {
			@Override
			public void execute(DependencyUpdatesTask updateDependencies) {
				updateDependencies.setDescription("Update the dependencies");
				updateDependencies.setCheckConstraints(true);
				updateDependencies.setOutputFormatter(new Closure<Void>(null) {
					@Override
					public Void call(Object argument) {
						Result result = (Result) argument;
						if (gitHubApi == null && updateDependenciesSettings.getUpdateMode() != UpdateDependenciesExtension.UpdateMode.COMMIT) {
							gitHubApi = new GitHubApi(updateDependenciesSettings.getGitHub().getAccessToken());
						}
						updateDependencies(result, project, updateDependenciesSettings);
						updateGradleVersion(result, project, updateDependenciesSettings);
						return null;
					}
				});
				updateDependencies.resolutionStrategy(new Action<ResolutionStrategyWithCurrent>() {
					@Override
					public void execute(ResolutionStrategyWithCurrent resolution) {
						resolution.componentSelection(new Action<ComponentSelectionRulesWithCurrent>() {
							@Override
							public void execute(ComponentSelectionRulesWithCurrent components) {
								updateDependenciesSettings.getExcludes().getActions().forEach((action) -> {
									components.all(action);
								});
								updateDependenciesSettings.getExcludes().getComponents().forEach((action) -> {
									action.execute(components);
								});
								components.all((selection) -> {
									ModuleComponentIdentifier candidate = selection.getCandidate();
									if (candidate.getGroup().startsWith("org.apache.directory.") && !candidate.getVersion().equals(selection.getCurrentVersion())) {
										selection.reject("org.apache.directory.* has breaking changes in newer versions");
									}
								});
								String jaxbBetaRegex = ".*?b\\d+.*";
								components.withModule("javax.xml.bind:jaxb-api", excludeWithRegex(jaxbBetaRegex, "Reject jaxb-api beta versions"));
								components.withModule("com.sun.xml.bind:jaxb-impl", excludeWithRegex(jaxbBetaRegex, "Reject jaxb-api beta versions"));
								components.withModule("commons-collections:commons-collections", excludeWithRegex("^\\d{3,}.*", "Reject commons-collections date based releases"));
							}
						});
					}
				});
			}
		});
	}

	private void updateDependencies(Result result, Project project, UpdateDependenciesExtension updateDependenciesSettings) {
		SortedSet<DependencyOutdated> dependencies = result.getOutdated().getDependencies();
		if (dependencies.isEmpty()) {
			return;
		}
		Map<String, List<DependencyOutdated>> groups = new LinkedHashMap<>();
		dependencies.forEach(outdated -> {
			groups.computeIfAbsent(outdated.getGroup(), (key) -> new ArrayList<>()).add(outdated);
		});
		List<DependencyOutdated> nimbusds = groups.getOrDefault("com.nimbusds", new ArrayList<>());
		DependencyOutdated oidcSdc = nimbusds.stream().filter(d -> d.getName().equals(OIDC_SDK_NAME)).findFirst().orElseGet(() -> null);
		if(oidcSdc != null) {
			String oidcVersion = updatedVersion(oidcSdc);
			String jwtVersion = TransitiveDependencyLookupUtils.lookupJwtVersion(oidcVersion);

			Dependency nimbusJoseJwtDependency = result.getCurrent().getDependencies().stream().filter(d -> d.getName().equals(NIMBUS_JOSE_JWT_NAME)).findFirst().get();
			DependencyOutdated outdatedJwt = new DependencyOutdated();
			outdatedJwt.setVersion(nimbusJoseJwtDependency.getVersion());
			outdatedJwt.setGroup(oidcSdc.getGroup());
			outdatedJwt.setName(NIMBUS_JOSE_JWT_NAME);
			VersionAvailable available = new VersionAvailable();
			available.setRelease(jwtVersion);
			outdatedJwt.setAvailable(available);
			nimbusds.add(outdatedJwt);
		}
		File gradlePropertiesFile = project.getRootProject().file(Project.GRADLE_PROPERTIES);
		Mono<GitHubApi.FindCreateIssueResult> createIssueResult = createIssueResultMono(updateDependenciesSettings);
		List<File> filesWithDependencies = updateDependenciesSettings.getFiles().get();
		groups.forEach((group, outdated) -> {
			outdated.forEach((dependency) -> {
				String ga = dependency.getGroup() + ":" + dependency.getName() + ":";
				String originalDependency = ga + dependency.getVersion();
				String replacementDependency = ga + updatedVersion(dependency);
				System.out.println("Update " + originalDependency + " to " + replacementDependency);
				filesWithDependencies.forEach((fileWithDependency) -> {
					updateDependencyInlineVersion(fileWithDependency, dependency);
					updateDependencyWithVersionVariable(fileWithDependency, gradlePropertiesFile, dependency);
				});
			});

			// commit
			DependencyOutdated firstDependency = outdated.get(0);
			String updatedVersion = updatedVersion(firstDependency);
			String title = outdated.size() == 1 ? "Update " + firstDependency.getName() + " to " + updatedVersion : "Update " + firstDependency.getGroup() + " to " + updatedVersion;
			afterGroup(updateDependenciesSettings, project.getRootDir(), title, createIssueResult);
		});
	}

	private void afterGroup(UpdateDependenciesExtension updateDependenciesExtension, File rootDir, String title, Mono<GitHubApi.FindCreateIssueResult> createIssueResultMono) {

		String commitMessage = title;
		if (updateDependenciesExtension.getUpdateMode() == UpdateDependenciesExtension.UpdateMode.GITHUB_ISSUE) {
			GitHubApi.FindCreateIssueResult createIssueResult = createIssueResultMono.block();
			Integer issueNumber = gitHubApi.createIssue(createIssueResult.getRepositoryId(), title, createIssueResult.getLabelIds(), createIssueResult.getMilestoneId(), createIssueResult.getAssigneeId()).delayElement(Duration.ofSeconds(1)).block();
			commitMessage += "\n\nCloses gh-" + issueNumber;
		}
		runCommand(rootDir, "git", "commit", "-am", commitMessage);
	}

	private Mono<GitHubApi.FindCreateIssueResult> createIssueResultMono(UpdateDependenciesExtension updateDependenciesExtension) {
		return Mono.defer(() -> {
			UpdateDependenciesExtension.GitHub gitHub = updateDependenciesExtension.getGitHub();
			return gitHubApi.findCreateIssueInput(gitHub.getOrganization(), gitHub.getRepository(), gitHub.getMilestone()).cache();
		});
	}

	private void updateGradleVersion(Result result, Project project, UpdateDependenciesExtension updateDependenciesSettings) {
		if (!result.getGradle().isEnabled()) {
			return;
		}
		GradleUpdateResult current = result.getGradle().getCurrent();
		GradleUpdateResult running = result.getGradle().getRunning();
		if (current.compareTo(running) > 0) {
			String title = "Update Gradle to " + current.getVersion();
			System.out.println(title);
			runCommand(project.getRootDir(), "./gradlew", "wrapper", "--gradle-version", current.getVersion(), "--no-daemon");
			afterGroup(updateDependenciesSettings, project.getRootDir(), title, createIssueResultMono(updateDependenciesSettings));
		}
	}

	private static Supplier<List<File>> defaultFiles(Project project) {
		return () -> {
			List<File> result = new ArrayList<>();
			result.add(project.getBuildFile());
			project.getChildProjects().values().forEach((childProject) ->
					result.add(childProject.getBuildFile())
			);
			result.add(project.getRootProject().file("buildSrc/build.gradle"));
			return result;
		};
	}

	static void runCommand(File dir, String... args) {
		try {
			Process process = new ProcessBuilder()
					.directory(dir)
					.command(args)
					.start();
			writeLinesTo(process.getInputStream(), System.out);
			writeLinesTo(process.getErrorStream(), System.out);
			if (process.waitFor() != 0) {
				new RuntimeException("Failed to run " + Arrays.toString(args));
			}
		} catch (IOException | InterruptedException e) {
			throw new RuntimeException("Failed to run " + Arrays.toString(args), e);
		}
	}

	static void writeLinesTo(InputStream input, PrintStream out) {
		Scanner scanner = new Scanner(input);
		while(scanner.hasNextLine()) {
			out.println(scanner.nextLine());
		}
	}


	static Action<ComponentSelectionWithCurrent> excludeWithRegex(String regex, String reason) {
		Pattern pattern = Pattern.compile(regex);
		return (selection) -> {
			String candidateVersion = selection.getCandidate().getVersion();
			if (pattern.matcher(candidateVersion).matches()) {
				selection.reject(candidateVersion + " is not allowed because it is " + reason);
			}
		};
	}

	static void updateDependencyInlineVersion(File buildFile, DependencyOutdated dependency){
		String ga = dependency.getGroup() + ":" + dependency.getName() + ":";
		String originalDependency = ga + dependency.getVersion();
		String replacementDependency = ga + updatedVersion(dependency);
		replaceFileText(buildFile, buildFileText -> buildFileText.replace(originalDependency, replacementDependency));
	}

	static void replaceFileText(File file, Function<String, String> replaceText) {
		String buildFileText = readString(file);
		String updatedBuildFileText = replaceText.apply(buildFileText);
		writeString(file, updatedBuildFileText);
	}

	private static String readString(File file) {
		try {
			byte[] bytes = Files.readAllBytes(file.toPath());
			return new String(bytes);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static void writeString(File file, String text) {
		try {
			Files.write(file.toPath(), text.getBytes());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	static void updateDependencyWithVersionVariable(File scanFile, File gradlePropertiesFile, DependencyOutdated dependency) {
		if (!gradlePropertiesFile.exists()) {
			return;
		}
		replaceFileText(gradlePropertiesFile, (gradlePropertiesText) -> {
			String ga = dependency.getGroup() + ":" + dependency.getName() + ":";
			Pattern pattern = Pattern.compile("\"" + ga + "\\$\\{?([^'\"]+?)\\}?\"");
			String buildFileText = readString(scanFile);
			Matcher matcher = pattern.matcher(buildFileText);
			while (matcher.find()) {
				String versionVariable = matcher.group(1);
				gradlePropertiesText = gradlePropertiesText.replace(versionVariable + "=" + dependency.getVersion(), versionVariable + "=" + updatedVersion(dependency));
			}
			return gradlePropertiesText;
		});
	}

	private static String updatedVersion(DependencyOutdated dependency) {
		VersionAvailable available = dependency.getAvailable();
		String release = available.getRelease();
		if (release != null) {
			return release;
		}
		return available.getMilestone();
	}
}
