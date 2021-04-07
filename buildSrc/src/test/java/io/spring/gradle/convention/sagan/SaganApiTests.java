/*
 * Copyright 2019-2020 the original author or authors.
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

package io.spring.gradle.convention.sagan;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.gradle.sagan.Release;
import org.springframework.gradle.sagan.SaganApi;

import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;


public class SaganApiTests {
	private MockWebServer server;

	private SaganApi sagan;

	private String baseUrl;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.sagan = new SaganApi("mock-oauth-token");
		this.baseUrl = this.server.url("/api").toString();
		this.sagan.setBaseUrl(this.baseUrl);
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void createWhenValidThenNoException() throws Exception {
		this.server.enqueue(new MockResponse());
		Release release = new Release();
		release.setVersion("5.6.0-SNAPSHOT");
		release.setApiDocUrl("https://docs.spring.io/spring-security/site/docs/{version}/api/");
		release.setReferenceDocUrl("https://docs.spring.io/spring-security/site/docs/{version}/reference/html5/");
		this.sagan.createReleaseForProject(release, "spring-security");
		RecordedRequest request = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(request.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/projects/spring-security/releases");
		assertThat(request.getMethod()).isEqualToIgnoringCase("post");
		assertThat(request.getHeaders().get("Authorization")).isEqualTo("Basic bm90LXVzZWQ6bW9jay1vYXV0aC10b2tlbg==");
		assertThat(request.getBody().readString(Charset.defaultCharset())).isEqualToIgnoringWhitespace("{\n" +
				"   \"version\":\"5.6.0-SNAPSHOT\",\n" +
				"   \"current\":false,\n" +
				"   \"referenceDocUrl\":\"https://docs.spring.io/spring-security/site/docs/{version}/reference/html5/\",\n" +
				"   \"apiDocUrl\":\"https://docs.spring.io/spring-security/site/docs/{version}/api/\"\n" +
				"}");
	}

	@Test
	public void deleteWhenValidThenNoException() throws Exception {
		this.server.enqueue(new MockResponse());
		this.sagan.deleteReleaseForProject("5.6.0-SNAPSHOT", "spring-security");
		RecordedRequest request = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(request.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/projects/spring-security/releases/5.6.0-SNAPSHOT");
		assertThat(request.getMethod()).isEqualToIgnoringCase("delete");
		assertThat(request.getHeaders().get("Authorization")).isEqualTo("Basic bm90LXVzZWQ6bW9jay1vYXV0aC10b2tlbg==");
		assertThat(request.getBody().readString(Charset.defaultCharset())).isEmpty();
	}
}
