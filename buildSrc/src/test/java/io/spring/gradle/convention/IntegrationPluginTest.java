/*
 * Copyright 2004-present the original author or authors.
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

import org.apache.commons.io.FileUtils;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class IntegrationPluginTest {
	Project rootProject;

	@AfterEach
	public void cleanup() throws Exception {
		if (rootProject != null) {
			FileUtils.deleteDirectory(rootProject.getProjectDir());
		}
	}

	@Test
	public void applyWhenNoSourceThenIntegrationTestTaskNull() {
		rootProject = ProjectBuilder.builder().build();
		rootProject.getPlugins().apply(JavaPlugin.class);
		rootProject.getPlugins().apply(IntegrationTestPlugin.class);

		assertThat(rootProject.getTasks().findByPath("integrationTest")).isNull();
	}

}
