/*
 * Copyright 2002-2021 the original author or authors.
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


package io.spring.gradle

import groovy.transform.CompileStatic
import groovy.transform.TypeChecked
import groovy.transform.TypeCheckingMode
import org.gradle.api.DefaultTask
import org.gradle.api.Task
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction

/**
 * Checkout a project template from a git repository.
 *
 * @author Marcus Da Coregio
 */
@CompileStatic
abstract class IncludeRepoTask extends DefaultTask {

	private static final String DEFAULT_URI_PREFIX = 'https://github.com/'

	/**
	 * Git repository to use. Will be prefixed with {@link #DEFAULT_URI_PREFIX} if it isn't already
	 * @return
	 */
	@Input
	abstract Property<String> getRepository();

	/**
	 * Git reference to use.
	 */
	@Input
	abstract Property<String> getRef()

	/**
	 * Directory where the project template should be copied.
	 */
	@OutputDirectory
	File outputDirectory = project.file("$project.buildDir/$name")

	@TaskAction
	void checkoutAndCopy() {
		outputDirectory.deleteDir()
		File checkoutDir = checkout(this, getRemoteUri(), ref.get())
		moveToOutputDir(checkoutDir, outputDirectory)
	}

	private static File cleanTemporaryDir(Task task, File tmpDir) {
		if (tmpDir.exists()) {
			task.project.delete(tmpDir)
		}
		return tmpDir
	}

	static File checkout(Task task, String remoteUri, String ref) {
		checkout(task, remoteUri, ref, task.getTemporaryDir())
	}

	@TypeChecked(TypeCheckingMode.SKIP)
	static File checkout(Task task, String remoteUri, String ref, File checkoutDir) {
		cleanTemporaryDir(task, checkoutDir)
		task.project.exec {
			commandLine = ["git", "clone", "--no-checkout", remoteUri, checkoutDir.absolutePath]
			errorOutput = System.err
		}
		task.project.exec {
			commandLine = ["git", "checkout", ref]
			workingDir = checkoutDir
			errorOutput = System.err
		}
		return checkoutDir
	}

	private static void moveToOutputDir(File tmpDir, File outputDirectory) {
		File baseDir = tmpDir
		baseDir.renameTo(outputDirectory)
	}

	private String getRemoteUri() {
		String remoteUri = this.repository.get()
		if (remoteUri.startsWith(DEFAULT_URI_PREFIX)) {
			return remoteUri
		}
		return DEFAULT_URI_PREFIX + remoteUri
	}
}
