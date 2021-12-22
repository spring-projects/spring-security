/*
 * Copyright 2002-2021 the original author or authors.
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

import java.io.IOException;

import com.google.gson.Gson;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.springframework.gradle.github.RepositoryRef;

/**
 * Manage GitHub releases.
 *
 * @author Steve Riesenberg
 */
public class GitHubReleaseApi {
	private String baseUrl = "https://api.github.com";

	private final OkHttpClient httpClient;
	private Gson gson = new Gson();

	public GitHubReleaseApi(String gitHubAccessToken) {
		this.httpClient = new OkHttpClient.Builder()
				.addInterceptor(new AuthorizationInterceptor(gitHubAccessToken))
				.build();
	}

	public void setBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
	}

	/**
	 * Publish a release with no binary attachments.
	 *
	 * @param repository The repository owner/name
	 * @param release The contents of the release
	 */
	public void publishRelease(RepositoryRef repository, Release release) {
		String url = this.baseUrl + "/repos/" + repository.getOwner() + "/" + repository.getName() + "/releases";
		String json = this.gson.toJson(release);
		RequestBody body = RequestBody.create(MediaType.parse("application/json"), json);
		Request request = new Request.Builder().url(url).post(body).build();
		try {
			Response response = this.httpClient.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException(String.format("Could not create release %s for repository %s/%s. Got response %s",
						release.getName(), repository.getOwner(), repository.getName(), response));
			}
		} catch (IOException ex) {
			throw new RuntimeException(String.format("Could not create release %s for repository %s/%s",
					release.getName(), repository.getOwner(), repository.getName()), ex);
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
