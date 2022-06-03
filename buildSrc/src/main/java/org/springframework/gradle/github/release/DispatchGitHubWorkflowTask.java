/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.gradle.github.release;

import org.gradle.api.Action;
import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.TaskAction;

import org.springframework.gradle.github.RepositoryRef;

/**
 * @author Steve Riesenberg
 */
public class DispatchGitHubWorkflowTask extends DefaultTask {
	@Input
	private RepositoryRef repository = new RepositoryRef();

	@Input
	private String gitHubAccessToken;

	@Input
	private String branch;

	@Input
	private String workflowId;

	@TaskAction
	public void dispatchGitHubWorkflow() {
		GitHubActionsApi gitHubActionsApi = new GitHubActionsApi(this.gitHubAccessToken);
		WorkflowDispatch workflowDispatch = new WorkflowDispatch(this.branch, null);
		gitHubActionsApi.dispatchWorkflow(this.repository, this.workflowId, workflowDispatch);
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
	}

	public String getBranch() {
		return branch;
	}

	public void setBranch(String branch) {
		this.branch = branch;
	}

	public String getWorkflowId() {
		return workflowId;
	}

	public void setWorkflowId(String workflowId) {
		this.workflowId = workflowId;
	}
}
