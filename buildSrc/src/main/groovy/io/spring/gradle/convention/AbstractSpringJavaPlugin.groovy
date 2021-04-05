/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package io.spring.gradle.convention;

import io.spring.gradle.propdeps.PropDepsMavenPlugin;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.GroovyPlugin;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.MavenPlugin;
import org.gradle.api.plugins.PluginManager;
import org.gradle.internal.impldep.org.apache.maven.Maven;
import org.gradle.plugins.ide.eclipse.EclipseWtpPlugin;
import org.gradle.plugins.ide.idea.IdeaPlugin;
import io.spring.gradle.propdeps.PropDepsEclipsePlugin;
import io.spring.gradle.propdeps.PropDepsIdeaPlugin;
import io.spring.gradle.propdeps.PropDepsPlugin;

/**
 * @author Rob Winch
 */
public abstract class AbstractSpringJavaPlugin implements Plugin<Project> {

	@Override
	public final void apply(Project project) {
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(JavaPlugin.class);
		pluginManager.apply(ManagementConfigurationPlugin.class);
		if (project.file("src/main/groovy").exists()
				|| project.file("src/test/groovy").exists()
				|| project.file("src/integration-test/groovy").exists()) {
			pluginManager.apply(GroovyPlugin.class);
		}
		pluginManager.apply("io.spring.convention.repository");
		pluginManager.apply(EclipseWtpPlugin);
		pluginManager.apply(IdeaPlugin);
		pluginManager.apply(PropDepsPlugin);
		pluginManager.apply(PropDepsEclipsePlugin);
		pluginManager.apply(PropDepsIdeaPlugin);
		project.getPlugins().withType(MavenPlugin) {
			pluginManager.apply(PropDepsMavenPlugin);
		}
		pluginManager.apply("io.spring.convention.tests-configuration");
		pluginManager.apply("io.spring.convention.integration-test");
		pluginManager.apply("io.spring.convention.dependency-set");
		pluginManager.apply("io.spring.convention.javadoc-options");
		pluginManager.apply("io.spring.convention.checkstyle");

		copyPropertyFromRootProjectTo("group", project);
		copyPropertyFromRootProjectTo("version", project);
		copyPropertyFromRootProjectTo("description", project);

		project.jar {
			manifest.attributes["Created-By"] =
					"${System.getProperty("java.version")} (${System.getProperty("java.specification.vendor")})"
			manifest.attributes["Implementation-Title"] = project.name
			manifest.attributes["Implementation-Version"] = project.version
			manifest.attributes["Automatic-Module-Name"] = project.name.replace('-', '.')
		}
		additionalPlugins(project);
	}

	private void copyPropertyFromRootProjectTo(String propertyName, Project project) {
		Project rootProject = project.getRootProject();
		Object property = rootProject.findProperty(propertyName);
		if(property != null) {
			project.setProperty(propertyName, property);
		}
	}

	protected abstract void additionalPlugins(Project project);
}
