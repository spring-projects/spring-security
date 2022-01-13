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
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.springframework.gradle.github.RepositoryRef;

public abstract class GitHubMilestoneNextReleaseTask extends DefaultTask {

	@Input
	private RepositoryRef repository = new RepositoryRef();

	@Input
	@Optional
	private String gitHubAccessToken;

	private GitHubMilestoneApi milestones = new GitHubMilestoneApi();

	@TaskAction
	public void calculateNextReleaseMilestone() throws IOException {
		String currentVersion = getProject().getVersion().toString();
		String nextPreRelease = this.milestones.getNextReleaseMilestone(this.repository, currentVersion);
		System.out.println("The next release milestone is: " + nextPreRelease);
		NextVersionYml nextVersionYml = new NextVersionYml();
		nextVersionYml.setVersion(nextPreRelease);
		File outputFile = getNextReleaseFile().get().getAsFile();
		FileWriter outputWriter = new FileWriter(outputFile);
		Yaml yaml = getYaml();
		yaml.dump(nextVersionYml, outputWriter);
	}

	@OutputFile
	public abstract RegularFileProperty getNextReleaseFile();

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

	private Yaml getYaml() {
		Representer representer = new Representer();
		representer.addClassTag(NextVersionYml.class, Tag.MAP);
		DumperOptions ymlOptions = new DumperOptions();
		ymlOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
		return new Yaml(representer, ymlOptions);
	}

}
