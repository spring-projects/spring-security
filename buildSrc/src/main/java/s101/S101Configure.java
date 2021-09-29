/*
 * Copyright 2002-2021 the original author or authors.
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

package s101;

import java.io.File;

import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.TaskAction;

public class S101Configure extends DefaultTask {
	@TaskAction
	public void configure() throws Exception {
		S101PluginExtension extension = getProject().getExtensions().getByType(S101PluginExtension.class);
		File buildDirectory = extension.getInstallationDirectory().get();
		File projectDirectory = extension.getConfigurationDirectory().get();
		S101Configurer configurer = new S101Configurer(getProject());
		configurer.configure(buildDirectory, projectDirectory);
	}


}
