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

import java.io.IOException;

import com.google.gson.Gson;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * @author Steve Riesenberg
 */
public class GitHubUserApi {
	private String baseUrl = "https://api.github.com";

	private final OkHttpClient httpClient;
	private Gson gson = new Gson();

	public GitHubUserApi(String gitHubAccessToken) {
		this.httpClient = new OkHttpClient.Builder()
				.addInterceptor(new AuthorizationInterceptor(gitHubAccessToken))
				.build();
	}

	public void setBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
	}

	/**
	 * Retrieve a GitHub user by the personal access token.
	 *
	 * @return The GitHub user
	 */
	public User getUser() {
		String url = this.baseUrl + "/user";
		Request request = new Request.Builder().url(url).get().build();
		try (Response response = this.httpClient.newCall(request).execute()) {
			if (!response.isSuccessful()) {
				throw new RuntimeException(
						String.format("Unable to retrieve GitHub user." +
								" Please check the personal access token and try again." +
								" Got response %s", response));
			}
			return this.gson.fromJson(response.body().charStream(), User.class);
		} catch (IOException ex) {
			throw new RuntimeException("Unable to retrieve GitHub user.", ex);
		}
	}

	private static class AuthorizationInterceptor implements Interceptor {
		private final String token;

		public AuthorizationInterceptor(String token) {
			this.token = token;
		}

		@Override
		public Response intercept(Chain chain) throws IOException {
			Request request = chain.request().newBuilder()
					.addHeader("Authorization", "Bearer " + this.token)
					.build();

			return chain.proceed(request);
		}
	}
}
