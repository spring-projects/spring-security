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

package org.springframework.gradle.sagan;

import com.google.gson.Gson;
import okhttp3.*;

import java.io.IOException;
import java.util.Base64;

/**
 * Implements necessary calls to the Sagan API See https://github.com/spring-io/sagan/blob/master/sagan-site/src/docs/asciidoc/index.adoc
 */
public class SaganApi {
	private String baseUrl = "https://spring.io/api";

	private OkHttpClient client;
	private Gson gson = new Gson();

	public SaganApi(String gitHubToken) {
		this.client = new OkHttpClient.Builder()
				.addInterceptor(new BasicInterceptor("not-used", gitHubToken))
				.build();
	}

	public void setBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
	}

	public void createReleaseForProject(Release release, String projectName) {
		String url = this.baseUrl + "/projects/" + projectName + "/releases";
		String releaseJsonString = gson.toJson(release);
		RequestBody body = RequestBody.create(MediaType.parse("application/json"), releaseJsonString);
		Request request = new Request.Builder()
			.url(url)
			.post(body)
			.build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException("Could not create release " + release + ". Got response " + response);
			}
		} catch (IOException fail) {
			throw new RuntimeException("Could not create release " + release, fail);
		}
	}

	public void deleteReleaseForProject(String release, String projectName) {
		String url = this.baseUrl + "/projects/" + projectName + "/releases/" + release;
		Request request = new Request.Builder()
				.url(url)
				.delete()
				.build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException("Could not delete release " + release + ". Got response " + response);
			}
		} catch (IOException fail) {
			throw new RuntimeException("Could not delete release " + release, fail);
		}
	}

	private static class BasicInterceptor implements Interceptor {

		private final String token;

		public BasicInterceptor(String username, String token) {
			this.token = Base64.getEncoder().encodeToString((username + ":" + token).getBytes());
		}

		@Override
		public okhttp3.Response intercept(Chain chain) throws IOException {
			Request request = chain.request().newBuilder()
					.addHeader("Authorization", "Basic " + this.token).build();
			return chain.proceed(request);
		}
	}
}
