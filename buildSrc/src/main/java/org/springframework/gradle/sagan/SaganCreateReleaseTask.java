/*
 * Copyright 2019-2023 the original author or authors.
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

package org.springframework.gradle.sagan;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.TaskAction;

import org.springframework.gradle.github.user.GitHubUserApi;
import org.springframework.gradle.github.user.User;
import org.springframework.util.Assert;

public class SaganCreateReleaseTask extends DefaultTask {

	private static final Pattern VERSION_PATTERN = Pattern.compile("^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-.+)?$");

	@Input
	private String gitHubAccessToken;
	@Input
	private String version;
	@Input
	private String apiDocUrl;
	@Input
	private String referenceDocUrl;
	@Input
	private String projectName;

	@TaskAction
	public void saganCreateRelease() {
		GitHubUserApi github = new GitHubUserApi(this.gitHubAccessToken);
		User user = github.getUser();

		// Antora reference docs URLs for snapshots do not contain -SNAPSHOT
		String referenceDocUrl = this.referenceDocUrl;
		if (this.version.endsWith("-SNAPSHOT")) {
			Matcher versionMatcher = VERSION_PATTERN.matcher(this.version);
			Assert.isTrue(versionMatcher.matches(), "Version " + this.version + " does not match expected pattern");
			String majorVersion = versionMatcher.group(1);
			String minorVersion = versionMatcher.group(2);
			String majorMinorVersion = String.format("%s.%s-SNAPSHOT", majorVersion, minorVersion);
			referenceDocUrl = this.referenceDocUrl.replace("{version}", majorMinorVersion);
		}

		SaganApi sagan = new SaganApi(user.getLogin(), this.gitHubAccessToken);
		Release release = new Release();
		release.setVersion(this.version);
		release.setApiDocUrl(this.apiDocUrl);
		release.setReferenceDocUrl(referenceDocUrl);
		sagan.createReleaseForProject(release, this.projectName);
	}

	public String getGitHubAccessToken() {
		return gitHubAccessToken;
	}

	public void setGitHubAccessToken(String gitHubAccessToken) {
		this.gitHubAccessToken = gitHubAccessToken;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getApiDocUrl() {
		return apiDocUrl;
	}

	public void setApiDocUrl(String apiDocUrl) {
		this.apiDocUrl = apiDocUrl;
	}

	public String getReferenceDocUrl() {
		return referenceDocUrl;
	}

	public void setReferenceDocUrl(String referenceDocUrl) {
		this.referenceDocUrl = referenceDocUrl;
	}

	public String getProjectName() {
		return projectName;
	}

	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}

}
