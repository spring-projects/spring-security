/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.TaskProvider;

public class VerifyDependenciesVersionsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		TaskProvider<VerifyDependenciesVersionsTask> verifyDependenciesVersionsTaskProvider = project.getTasks().register("verifyDependenciesVersions", VerifyDependenciesVersionsTask.class, (task) -> {
			task.setGroup("Verification");
			task.setDescription("Verify that specific dependencies are using the same version");
			List<Configuration> allConfigurations = new ArrayList<>(getConfigurations(project));
			task.setConfigurations(allConfigurations);
		});
		project.getTasks().named(JavaBasePlugin.CHECK_TASK_NAME, checkTask -> checkTask.dependsOn(verifyDependenciesVersionsTaskProvider));
	}

	private List<Configuration> getConfigurations(Project rootProject) {
		List<Configuration> configurations = new ArrayList<>();
		for (Project project : rootProject.getAllprojects()) {
			List<Configuration> runtimeClasspath = project.getConfigurations().stream()
					.filter(Configuration::isCanBeResolved)
					.filter((config) -> config.getName().equals("runtimeClasspath"))
					.toList();
			configurations.addAll(runtimeClasspath);
		}
		return configurations;
	}

	public static class VerifyDependenciesVersionsTask extends DefaultTask {

		private List<Configuration> configurations;

		public void setConfigurations(List<Configuration> configurations) {
			this.configurations = configurations;
		}

		@TaskAction
		public void verify() {
			Map<String, List<Artifact>> artifacts = getDependencies(this.configurations);
			List<Artifact> oauth2OidcSdk = artifacts.get("oauth2-oidc-sdk");
			List<Artifact> nimbusJoseJwt = artifacts.get("nimbus-jose-jwt");
			if (oauth2OidcSdk == null) {
				// Could not resolve oauth2-oidc-sdk
				return;
			}
			if (oauth2OidcSdk.size() > 1) {
				throw new IllegalStateException("Found multiple versions of oauth2-oidc-sdk: " + oauth2OidcSdk);
			}
			Artifact oauth2OidcSdkArtifact = oauth2OidcSdk.get(0);
			String nimbusJoseJwtVersion = TransitiveDependencyLookupUtils.lookupJwtVersion(oauth2OidcSdkArtifact.version());
			List<Artifact> differentVersions = nimbusJoseJwt.stream()
					.filter((artifact) -> !artifact.version().equals(nimbusJoseJwtVersion))
					.filter((artifact -> !artifact.configurationName().contains("spring-security-cas"))) // CAS uses a different version
					.toList();
			if (!differentVersions.isEmpty()) {
				String message = "Found transitive nimbus-jose-jwt version [" + nimbusJoseJwtVersion + "] in oauth2-oidc-sdk " + oauth2OidcSdkArtifact
						+ ", but the project contains a different version of nimbus-jose-jwt " + differentVersions
						+ ". Please align the versions of nimbus-jose-jwt.";
				throw new IllegalStateException(message);
			}
		}

		private Map<String, List<Artifact>> getDependencies(List<Configuration> configurations) {
			return configurations.stream()
					.flatMap((configuration) -> {
						return configuration.getIncoming().getResolutionResult().getAllDependencies().stream()
								.map((dep) -> {
									String[] nameParts = dep.getRequested().getDisplayName().split(":");
									if (nameParts.length > 2) {
										return new Artifact(nameParts[1], nameParts[2], configuration.toString());
									}
									return null;
								});
					})
					.filter(Objects::nonNull)
					.distinct()
					.collect(Collectors.groupingBy(Artifact::name));
		}

	}

	private record Artifact(String name, String version, String configurationName) {
	}

}
