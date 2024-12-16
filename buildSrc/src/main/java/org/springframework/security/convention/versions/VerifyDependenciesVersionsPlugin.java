/*
 * Copyright 2002-2024 the original author or authors.
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

import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Dependency;
import org.gradle.api.artifacts.MinimalExternalModuleDependency;
import org.gradle.api.artifacts.VersionCatalog;
import org.gradle.api.artifacts.VersionCatalogsExtension;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.Provider;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.TaskExecutionException;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.api.tasks.VerificationException;

import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

public class VerifyDependenciesVersionsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		VersionCatalog versionCatalog = project.getExtensions().getByType(VersionCatalogsExtension.class).named("libs");
		Optional<Provider<MinimalExternalModuleDependency>> oauth2OidcSdk = versionCatalog.findLibrary("com-nimbusds-oauth2-oidc-sdk");
		Optional<Provider<MinimalExternalModuleDependency>> nimbusJoseJwt = versionCatalog.findLibrary("com-nimbusds-nimbus-jose-jwt");

		if (oauth2OidcSdk.isEmpty()) {
			throw new VerificationException("Library [com-nimbusds-oauth2-oidc-sdk] does not exist in the version catalog named libs.");
		}

		if (nimbusJoseJwt.isEmpty()) {
			throw new VerificationException("Library [com-nimbusds-nimbus-jose-jwt] does not exist in the version catalog named libs.");
		}

		TaskProvider<VerifyDependenciesVersionsTask> verifyDependenciesVersionsTaskProvider = project.getTasks().register("verifyDependenciesVersions", VerifyDependenciesVersionsTask.class, (task) -> {
			task.setGroup("Verification");
			task.setDescription("Verify that specific dependencies are using the same version");
			task.getOauth2OidcSdkVersion().convention(oauth2OidcSdk.get().map(Dependency::getVersion));
			task.getExpectedNimbusJoseJwtVersion().convention(nimbusJoseJwt.get().map(Dependency::getVersion));
			task.getOutputFile().convention(project.getLayout().getBuildDirectory().file("verify-dependencies-versions"));
		});
		project.getTasks().named(JavaBasePlugin.CHECK_TASK_NAME, checkTask -> checkTask.dependsOn(verifyDependenciesVersionsTaskProvider));
	}

	@CacheableTask
	public abstract static class VerifyDependenciesVersionsTask extends DefaultTask {

		@Input
		abstract Property<String> getOauth2OidcSdkVersion();

		@Input
		abstract Property<String> getExpectedNimbusJoseJwtVersion();

		@OutputFile
		abstract RegularFileProperty getOutputFile();

		@TaskAction
		public void verify()  {
			String oauth2OidcSdkVersion = this.getOauth2OidcSdkVersion().get();
			String transitiveNimbusJoseJwtVersion = TransitiveDependencyLookupUtils.lookupJwtVersion(oauth2OidcSdkVersion);
			String expectedNimbusJoseJwtVersion = this.getExpectedNimbusJoseJwtVersion().get();
			if (!transitiveNimbusJoseJwtVersion.equals(expectedNimbusJoseJwtVersion)) {
				String message = String.format("Found transitive nimbus-jose-jwt:%s in oauth2-oidc-sdk:%s, but the project contains a different version of nimbus-jose-jwt [%s]. Please align the versions.", transitiveNimbusJoseJwtVersion, oauth2OidcSdkVersion, expectedNimbusJoseJwtVersion);
				throw new VerificationException(message);
			}
			String message = String.format("Found transitive nimbus-jose-jwt:%s in oauth2-oidc-sdk:%s, the project contains expected version of nimbus-jose-jwt [%s]. Verified all versions align.", transitiveNimbusJoseJwtVersion, oauth2OidcSdkVersion, expectedNimbusJoseJwtVersion);
			try {
				Files.writeString(getOutputFile().get().getAsFile().toPath(), message);
			} catch (IOException e) {
				throw new TaskExecutionException(this, e);
			}
		}
	}
}
