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
import java.util.LinkedHashMap;
import java.util.Map;
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
public class GitHubActionsApiTests {
	private GitHubActionsApi gitHubActionsApi;

	private MockWebServer server;

	private String baseUrl;

	private RepositoryRef repository;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.baseUrl = this.server.url("/api").toString();
		this.gitHubActionsApi = new GitHubActionsApi("mock-oauth-token");
		this.gitHubActionsApi.setBaseUrl(this.baseUrl);
		this.repository = new RepositoryRef("spring-projects", "spring-security");
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void dispatchWorkflowWhenValidParametersThenSuccess() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(204));

		Map<String, Object> inputs = new LinkedHashMap<>();
		inputs.put("input-1", "value");
		inputs.put("input-2", false);
		WorkflowDispatch workflowDispatch = new WorkflowDispatch("main", inputs);
		this.gitHubActionsApi.dispatchWorkflow(this.repository, "test-workflow.yml", workflowDispatch);

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("post");
		assertThat(recordedRequest.getRequestUrl().toString())
				.isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/actions/workflows/test-workflow.yml/dispatches");
		assertThat(recordedRequest.getBody().readString(Charset.defaultCharset()))
				.isEqualTo("{\"ref\":\"main\",\"inputs\":{\"input-1\":\"value\",\"input-2\":false}}");
	}

	@Test
	public void dispatchWorkflowWhenErrorResponseThenException() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(400));

		WorkflowDispatch workflowDispatch = new WorkflowDispatch("main", null);
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.gitHubActionsApi.dispatchWorkflow(this.repository, "test-workflow.yml", workflowDispatch));
	}
}
