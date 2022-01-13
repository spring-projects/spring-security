/*
 * Copyright 2019-2022 the original author or authors.
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

package org.springframework.gradle.github.milestones;

import org.gradle.api.Action;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.TaskAction;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.springframework.gradle.github.RepositoryRef;

public abstract class GitHubMilestoneNextVersionDueTodayTask extends DefaultTask {

	@Input
	private RepositoryRef repository = new RepositoryRef();

	@Input
	@Optional
	private String gitHubAccessToken;

	@InputFile
	public abstract RegularFileProperty getNextVersionFile();

	private GitHubMilestoneApi milestones = new GitHubMilestoneApi();

	@TaskAction
	public void checkReleaseDueToday() throws FileNotFoundException {
		File nextVersionFile = getNextVersionFile().getAsFile().get();
		Yaml yaml = new Yaml(new Constructor(NextVersionYml.class));
		NextVersionYml nextVersionYml = yaml.load(new FileInputStream(nextVersionFile));
		String nextVersion = nextVersionYml.getVersion();
		if (nextVersion == null) {
			throw new IllegalArgumentException(
					"Could not find version property in provided file " + nextVersionFile.getName());
		}
		boolean milestoneDueToday = this.milestones.isMilestoneDueToday(this.repository, nextVersion);
		if (!milestoneDueToday) {
			throw new IllegalStateException("The milestone with the title " + nextVersion + " in the repository "
					+ this.repository + " is not due yet");
		}
		System.out.println("The milestone with the title " + nextVersion + " in the repository " + this.repository
				+ " is due today");
	}

	public RepositoryRef getRepository() {
		return repository;
	}

	public void repository(Action<RepositoryRef> repository) {
		repository.execute(this.repository);
	}

	public void setRepository(RepositoryRef repository) {
		this.repository = repository;
	}

	public String getGitHubAccessToken() {
		return gitHubAccessToken;
	}

	public void setGitHubAccessToken(String gitHubAccessToken) {
		this.gitHubAccessToken = gitHubAccessToken;
		this.milestones = new GitHubMilestoneApi(gitHubAccessToken);
	}

}
