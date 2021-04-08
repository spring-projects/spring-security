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

package org.springframework.gradle.github.milestones;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.List;

public class GitHubMilestoneApi {
	private String baseUrl = "https://api.github.com";

	private OkHttpClient client;

	private Gson gson = new Gson();

	public GitHubMilestoneApi() {
		this.client = new OkHttpClient.Builder().build();
	}

	public GitHubMilestoneApi(String gitHubToken) {
		this.client = new OkHttpClient.Builder()
				.addInterceptor(new AuthorizationInterceptor(gitHubToken))
				.build();
	}

	public void setBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
	}

	public long findMilestoneNumberByTitle(RepositoryRef repositoryRef, String milestoneTitle) {
		String url = this.baseUrl + "/repos/" + repositoryRef.getOwner() + "/" + repositoryRef.getName() + "/milestones?per_page=100";
		Request request = new Request.Builder().get().url(url)
				.build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException("Could not find milestone with title " + milestoneTitle + " for repository " + repositoryRef + ". Response " + response);
			}
			List<Milestone> milestones = this.gson.fromJson(response.body().charStream(), new TypeToken<List<Milestone>>(){}.getType());
			for (Milestone milestone : milestones) {
				if (milestoneTitle.equals(milestone.getTitle())) {
					return milestone.getNumber();
				}
			}
			if (milestones.size() <= 100) {
				throw new RuntimeException("Could not find open milestone with title " + milestoneTitle + " for repository " + repositoryRef + " Got " + milestones);
			}
			throw new RuntimeException("It is possible there are too many open milestones open (only 100 are supported). Could not find open milestone with title " + milestoneTitle + " for repository " + repositoryRef + " Got " + milestones);
		} catch (IOException e) {
			throw new RuntimeException("Could not find open milestone with title " + milestoneTitle + " for repository " + repositoryRef, e);
		}
	}

	public boolean isOpenIssuesForMilestoneNumber(RepositoryRef repositoryRef, long milestoneNumber) {
		String url = this.baseUrl + "/repos/" + repositoryRef.getOwner() + "/" + repositoryRef.getName() + "/issues?per_page=1&milestone=" + milestoneNumber;
		Request request = new Request.Builder().get().url(url)
				.build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException("Could not find issues for milestone number " + milestoneNumber + " for repository " + repositoryRef + ". Response " + response);
			}
			List<Object> issues = this.gson.fromJson(response.body().charStream(), new TypeToken<List<Object>>(){}.getType());
			return !issues.isEmpty();
		} catch (IOException e) {
			throw new RuntimeException("Could not find issues for milestone number " + milestoneNumber + " for repository " + repositoryRef, e);
		}
	}

//	public boolean isOpenIssuesForMilestoneName(String owner, String repository, String milestoneName) {
//
//	}


	private static class AuthorizationInterceptor implements Interceptor {

		private final String token;

		public AuthorizationInterceptor(String token) {
			this.token = token;
		}

		@Override
		public okhttp3.Response intercept(Chain chain) throws IOException {
			Request request = chain.request().newBuilder()
					.addHeader("Authorization", "Bearer " + this.token).build();
			return chain.proceed(request);
		}
	}
}
