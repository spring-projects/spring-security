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

import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.gradle.github.RepositoryRef;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Steve Riesenberg
 */
public class GitHubReleaseApiTests {
	private GitHubReleaseApi gitHubReleaseApi;

	private MockWebServer server;

	private String baseUrl;

	private RepositoryRef repository;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.baseUrl = this.server.url("/api").toString();
		this.gitHubReleaseApi = new GitHubReleaseApi("mock-oauth-token");
		this.gitHubReleaseApi.setBaseUrl(this.baseUrl);
		this.repository = new RepositoryRef("spring-projects", "spring-security");
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void publishReleaseWhenValidParametersThenSuccess() throws Exception {
		String responseJson = "{\n" +
				"  \"url\": \"https://api.github.com/spring-projects/spring-security/releases/1\",\n" +
				"  \"html_url\": \"https://github.com/spring-projects/spring-security/releases/tags/v1.0.0\",\n" +
				"  \"assets_url\": \"https://api.github.com/spring-projects/spring-security/releases/1/assets\",\n" +
				"  \"upload_url\": \"https://uploads.github.com/spring-projects/spring-security/releases/1/assets{?name,label}\",\n" +
				"  \"tarball_url\": \"https://api.github.com/spring-projects/spring-security/tarball/v1.0.0\",\n" +
				"  \"zipball_url\": \"https://api.github.com/spring-projects/spring-security/zipball/v1.0.0\",\n" +
				"  \"discussion_url\": \"https://github.com/spring-projects/spring-security/discussions/90\",\n" +
				"  \"id\": 1,\n" +
				"  \"node_id\": \"MDc6UmVsZWFzZTE=\",\n" +
				"  \"tag_name\": \"v1.0.0\",\n" +
				"  \"target_commitish\": \"main\",\n" +
				"  \"name\": \"v1.0.0\",\n" +
				"  \"body\": \"Description of the release\",\n" +
				"  \"draft\": false,\n" +
				"  \"prerelease\": false,\n" +
				"  \"created_at\": \"2013-02-27T19:35:32Z\",\n" +
				"  \"published_at\": \"2013-02-27T19:35:32Z\",\n" +
				"  \"author\": {\n" +
				"    \"login\": \"sjohnr\",\n" +
				"    \"id\": 1,\n" +
				"    \"node_id\": \"MDQ6VXNlcjE=\",\n" +
				"    \"avatar_url\": \"https://github.com/images/avatar.gif\",\n" +
				"    \"gravatar_id\": \"\",\n" +
				"    \"url\": \"https://api.github.com/users/sjohnr\",\n" +
				"    \"html_url\": \"https://github.com/sjohnr\",\n" +
				"    \"followers_url\": \"https://api.github.com/users/sjohnr/followers\",\n" +
				"    \"following_url\": \"https://api.github.com/users/sjohnr/following{/other_user}\",\n" +
				"    \"gists_url\": \"https://api.github.com/users/sjohnr/gists{/gist_id}\",\n" +
				"    \"starred_url\": \"https://api.github.com/users/sjohnr/starred{/owner}{/repo}\",\n" +
				"    \"subscriptions_url\": \"https://api.github.com/users/sjohnr/subscriptions\",\n" +
				"    \"organizations_url\": \"https://api.github.com/users/sjohnr/orgs\",\n" +
				"    \"repos_url\": \"https://api.github.com/users/sjohnr/repos\",\n" +
				"    \"events_url\": \"https://api.github.com/users/sjohnr/events{/privacy}\",\n" +
				"    \"received_events_url\": \"https://api.github.com/users/sjohnr/received_events\",\n" +
				"    \"type\": \"User\",\n" +
				"    \"site_admin\": false\n" +
				"  },\n" +
				"  \"assets\": [\n" +
				"    {\n" +
				"      \"url\": \"https://api.github.com/spring-projects/spring-security/releases/assets/1\",\n" +
				"      \"browser_download_url\": \"https://github.com/spring-projects/spring-security/releases/download/v1.0.0/example.zip\",\n" +
				"      \"id\": 1,\n" +
				"      \"node_id\": \"MDEyOlJlbGVhc2VBc3NldDE=\",\n" +
				"      \"name\": \"example.zip\",\n" +
				"      \"label\": \"short description\",\n" +
				"      \"state\": \"uploaded\",\n" +
				"      \"content_type\": \"application/zip\",\n" +
				"      \"size\": 1024,\n" +
				"      \"download_count\": 42,\n" +
				"      \"created_at\": \"2013-02-27T19:35:32Z\",\n" +
				"      \"updated_at\": \"2013-02-27T19:35:32Z\",\n" +
				"      \"uploader\": {\n" +
				"        \"login\": \"sjohnr\",\n" +
				"        \"id\": 1,\n" +
				"        \"node_id\": \"MDQ6VXNlcjE=\",\n" +
				"        \"avatar_url\": \"https://github.com/images/avatar.gif\",\n" +
				"        \"gravatar_id\": \"\",\n" +
				"        \"url\": \"https://api.github.com/users/sjohnr\",\n" +
				"        \"html_url\": \"https://github.com/sjohnr\",\n" +
				"        \"followers_url\": \"https://api.github.com/users/sjohnr/followers\",\n" +
				"        \"following_url\": \"https://api.github.com/users/sjohnr/following{/other_user}\",\n" +
				"        \"gists_url\": \"https://api.github.com/users/sjohnr/gists{/gist_id}\",\n" +
				"        \"starred_url\": \"https://api.github.com/users/sjohnr/starred{/owner}{/repo}\",\n" +
				"        \"subscriptions_url\": \"https://api.github.com/users/sjohnr/subscriptions\",\n" +
				"        \"organizations_url\": \"https://api.github.com/users/sjohnr/orgs\",\n" +
				"        \"repos_url\": \"https://api.github.com/users/sjohnr/repos\",\n" +
				"        \"events_url\": \"https://api.github.com/users/sjohnr/events{/privacy}\",\n" +
				"        \"received_events_url\": \"https://api.github.com/users/sjohnr/received_events\",\n" +
				"        \"type\": \"User\",\n" +
				"        \"site_admin\": false\n" +
				"      }\n" +
				"    }\n" +
				"  ]\n" +
				"}";
		this.server.enqueue(new MockResponse().setBody(responseJson));
		this.gitHubReleaseApi.publishRelease(this.repository, Release.tag("1.0.0").build());

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("post");
		assertThat(recordedRequest.getRequestUrl().toString())
				.isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/releases");
		assertThat(recordedRequest.getBody().readString(Charset.defaultCharset()))
				.isEqualTo("{\"tag_name\":\"1.0.0\",\"draft\":false,\"prerelease\":false,\"generate_release_notes\":false}");
	}

	@Test
	public void publishReleaseWhenErrorResponseThenException() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(400));
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.gitHubReleaseApi.publishRelease(this.repository, Release.tag("1.0.0").build()));
	}
}
