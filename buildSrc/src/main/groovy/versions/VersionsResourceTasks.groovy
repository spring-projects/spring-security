/*
 * Copyright 2002-2018 the original author or authors.
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
package versions

import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

/**
 * @author Rob Winch
 */
class VersionsResourceTasks extends DefaultTask {
	@OutputFile
	File versionsFile;

	@Input
	Closure<Map<String,String>> versions;

	void setVersions(Map<String,String> versions) {
		this.versions = { versions };
	}

	void setVersions(Closure<Map<String,String>> versions) {
		this.versions = versions
	}

	@TaskAction
	void generateVersions() {
		versionsFile.parentFile.mkdirs()
		versionsFile.createNewFile()
		Properties versionsProperties = new Properties()
		versionsProperties.putAll(versions.call())
		versionsProperties.store(versionsFile.newWriter(), null)
	}
}
