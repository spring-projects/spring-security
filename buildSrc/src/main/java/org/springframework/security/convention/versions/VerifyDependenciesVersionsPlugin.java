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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.ModuleVersionIdentifier;
import org.gradle.api.tasks.TaskProvider;

public class VerifyDependenciesVersionsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		TaskProvider<Task> provider = project.getTasks().register("verifyDependenciesVersions", (verifyDependenciesVersionsTask) -> {
			verifyDependenciesVersionsTask.setGroup("Verification");
			verifyDependenciesVersionsTask.setDescription("Verify that specific dependencies are using the same version");
			List<Configuration> allConfigurations = new ArrayList<>();
			allConfigurations.addAll(getConfigurations(project));
			allConfigurations.addAll(getSubprojectsConfigurations(project.getSubprojects()));
			verifyDependenciesVersionsTask.getInputs().property("dependenciesVersions", new DependencySupplier(allConfigurations));
			verifyDependenciesVersionsTask.doLast((task) -> {
				DependencySupplier dependencies = (DependencySupplier) task.getInputs().getProperties().get("dependenciesVersions");
				Map<String, List<Artifact>> artifacts = dependencies.get();
				List<Artifact> oauth2OidcSdk = artifacts.get("oauth2-oidc-sdk");
				List<Artifact> nimbusJoseJwt = artifacts.get("nimbus-jose-jwt");
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
			});
		});
		project.getTasks().getByName("build").dependsOn(provider);
	}

	private List<Configuration> getConfigurations(Project project) {
		return project.getConfigurations().stream()
				.filter(Configuration::isCanBeResolved)
				.filter((config) -> config.getName().equals("runtimeClasspath"))
				.toList();
	}

	private List<Configuration> getSubprojectsConfigurations(Set<Project> subprojects) {
		if (subprojects.isEmpty()) {
			return Collections.emptyList();
		}
		List<Configuration> subprojectConfigurations = new ArrayList<>();
		for (Project subproject : subprojects) {
			subprojectConfigurations.addAll(getConfigurations(subproject));
			subprojectConfigurations.addAll(getSubprojectsConfigurations(subproject.getSubprojects()));
		}
		return subprojectConfigurations;
	}

	private record Artifact(String name, String version, String configurationName) {
	}

	private static final class DependencySupplier implements Supplier<Map<String, List<Artifact>>> {

		private final List<Configuration> configurations;

		private DependencySupplier(List<Configuration> configurations) {
			this.configurations = configurations;
		}

		@Override
		public Map<String, List<Artifact>> get() {
			return getDependencies(this.configurations);
		}

		private Map<String, List<Artifact>> getDependencies(List<Configuration> configurations) {
			return configurations.stream().flatMap((configuration) -> {
						return configuration.getResolvedConfiguration().getResolvedArtifacts().stream()
								.map((dep) -> {
									ModuleVersionIdentifier id = dep.getModuleVersion().getId();
									return new Artifact(id.getName(), id.getVersion(), configuration.toString());
								});
					})
					.distinct()
					.collect(Collectors.groupingBy(Artifact::name));
		}
	}

}
