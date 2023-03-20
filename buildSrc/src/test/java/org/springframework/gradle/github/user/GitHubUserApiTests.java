/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.gradle.github.user;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Steve Riesenberg
 */
public class GitHubUserApiTests {
	private GitHubUserApi gitHubUserApi;

	private MockWebServer server;

	private String baseUrl;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.baseUrl = this.server.url("/api").toString();
		this.gitHubUserApi = new GitHubUserApi("mock-oauth-token");
		this.gitHubUserApi.setBaseUrl(this.baseUrl);
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void getUserWhenValidParametersThenSuccess() {
		// @formatter:off
		String responseJson = "{\n" +
				"    \"avatar_url\": \"https://avatars.githubusercontent.com/u/583231?v=4\",\n" +
				"    \"bio\": null,\n" +
				"    \"blog\": \"https://github.blog\",\n" +
				"    \"company\": \"@github\",\n" +
				"    \"created_at\": \"2011-01-25T18:44:36Z\",\n" +
				"    \"email\": null,\n" +
				"    \"events_url\": \"https://api.github.com/users/octocat/events{/privacy}\",\n" +
				"    \"followers\": 8481,\n" +
				"    \"followers_url\": \"https://api.github.com/users/octocat/followers\",\n" +
				"    \"following\": 9,\n" +
				"    \"following_url\": \"https://api.github.com/users/octocat/following{/other_user}\",\n" +
				"    \"gists_url\": \"https://api.github.com/users/octocat/gists{/gist_id}\",\n" +
				"    \"gravatar_id\": \"\",\n" +
				"    \"hireable\": null,\n" +
				"    \"html_url\": \"https://github.com/octocat\",\n" +
				"    \"id\": 583231,\n" +
				"    \"location\": \"San Francisco\",\n" +
				"    \"login\": \"octocat\",\n" +
				"    \"name\": \"The Octocat\",\n" +
				"    \"node_id\": \"MDQ6VXNlcjU4MzIzMQ==\",\n" +
				"    \"organizations_url\": \"https://api.github.com/users/octocat/orgs\",\n" +
				"    \"public_gists\": 8,\n" +
				"    \"public_repos\": 8,\n" +
				"    \"received_events_url\": \"https://api.github.com/users/octocat/received_events\",\n" +
				"    \"repos_url\": \"https://api.github.com/users/octocat/repos\",\n" +
				"    \"site_admin\": false,\n" +
				"    \"starred_url\": \"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\n" +
				"    \"subscriptions_url\": \"https://api.github.com/users/octocat/subscriptions\",\n" +
				"    \"twitter_username\": null,\n" +
				"    \"type\": \"User\",\n" +
				"    \"updated_at\": \"2023-02-25T12:14:58Z\",\n" +
				"    \"url\": \"https://api.github.com/users/octocat\"\n" +
				"}";
		// @formatter:on
		this.server.enqueue(new MockResponse().setBody(responseJson));

		User user = this.gitHubUserApi.getUser();
		assertThat(user.getId()).isEqualTo(583231);
		assertThat(user.getLogin()).isEqualTo("octocat");
		assertThat(user.getName()).isEqualTo("The Octocat");
		assertThat(user.getUrl()).isEqualTo("https://api.github.com/users/octocat");
	}

	@Test
	public void getUserWhenErrorResponseThenException() {
		this.server.enqueue(new MockResponse().setResponseCode(400));
		// @formatter:off
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.gitHubUserApi.getUser());
		// @formatter:on
	}
}
