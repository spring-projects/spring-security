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

import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.MinimalExternalModuleDependency;
import org.gradle.api.artifacts.VersionCatalog;
import org.gradle.api.artifacts.VersionCatalogsExtension;
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.TaskProvider;

public class VerifyDependenciesVersionsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		TaskProvider<VerifyDependenciesVersionsTask> verifyDependenciesVersionsTaskProvider = project.getTasks().register("verifyDependenciesVersions", VerifyDependenciesVersionsTask.class, (task) -> {
			task.setGroup("Verification");
			task.setDescription("Verify that specific dependencies are using the same version");
			VersionCatalog versionCatalog = project.getExtensions().getByType(VersionCatalogsExtension.class).named("libs");
			MinimalExternalModuleDependency oauth2OidcSdk = versionCatalog.findLibrary("com-nimbusds-oauth2-oidc-sdk").get().get();
			MinimalExternalModuleDependency nimbusJoseJwt = versionCatalog.findLibrary("com-nimbusds-nimbus-jose-jwt").get().get();
			task.setOauth2OidcSdkVersion(oauth2OidcSdk.getVersion());
			task.setExpectedNimbusJoseJwtVersion(nimbusJoseJwt.getVersion());
		});
		project.getTasks().named(JavaBasePlugin.CHECK_TASK_NAME, checkTask -> checkTask.dependsOn(verifyDependenciesVersionsTaskProvider));
	}

	public static class VerifyDependenciesVersionsTask extends DefaultTask {

		private String oauth2OidcSdkVersion;

		private String expectedNimbusJoseJwtVersion;

		public void setOauth2OidcSdkVersion(String oauth2OidcSdkVersion) {
			this.oauth2OidcSdkVersion = oauth2OidcSdkVersion;
		}

		public void setExpectedNimbusJoseJwtVersion(String expectedNimbusJoseJwtVersion) {
			this.expectedNimbusJoseJwtVersion = expectedNimbusJoseJwtVersion;
		}

		@TaskAction
		public void verify() {
			String transitiveNimbusJoseJwtVersion = TransitiveDependencyLookupUtils.lookupJwtVersion(this.oauth2OidcSdkVersion);
			if (!transitiveNimbusJoseJwtVersion.equals(this.expectedNimbusJoseJwtVersion)) {
				String message = String.format("Found transitive nimbus-jose-jwt:%s in oauth2-oidc-sdk:%s, but the project contains a different version of nimbus-jose-jwt [%s]. Please align the versions.", transitiveNimbusJoseJwtVersion, this.oauth2OidcSdkVersion, this.expectedNimbusJoseJwtVersion);
				throw new IllegalStateException(message);
			}
		}

	}

}
