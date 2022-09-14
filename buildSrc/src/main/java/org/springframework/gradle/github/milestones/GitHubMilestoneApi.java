/*
 * Copyright 2019-2022 the original author or authors.
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

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.springframework.gradle.github.RepositoryRef;

public class GitHubMilestoneApi {
	private String baseUrl = "https://api.github.com";

	private OkHttpClient client;

	private final Gson gson = new GsonBuilder()
			.registerTypeAdapter(LocalDate.class, new LocalDateAdapter().nullSafe())
			.registerTypeAdapter(LocalDateTime.class, new LocalDateTimeAdapter().nullSafe())
			.create();

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
		List<Milestone> milestones = this.getMilestones(repositoryRef);
		for (Milestone milestone : milestones) {
			if (milestoneTitle.equals(milestone.getTitle())) {
				return milestone.getNumber();
			}
		}
		if (milestones.size() <= 100) {
			throw new RuntimeException("Could not find open milestone with title " + milestoneTitle + " for repository " + repositoryRef + " Got " + milestones);
		}
		throw new RuntimeException("It is possible there are too many open milestones (only 100 are supported). Could not find open milestone with title " + milestoneTitle + " for repository " + repositoryRef + " Got " + milestones);
	}

	public List<Milestone> getMilestones(RepositoryRef repositoryRef) {
		String url = this.baseUrl + "/repos/" + repositoryRef.getOwner() + "/" + repositoryRef.getName() + "/milestones?per_page=100";
		Request request = new Request.Builder().get().url(url)
				.build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException("Could not retrieve milestones for repository " + repositoryRef + ". Response " + response);
			}
			return this.gson.fromJson(response.body().charStream(), new TypeToken<List<Milestone>>(){}.getType());
		} catch (IOException e) {
			throw new RuntimeException("Could not retrieve milestones for repository " + repositoryRef, e);
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

	/**
	 * Check if the given milestone is due today or past due.
	 *
	 * @param repositoryRef The repository owner/name
	 * @param milestoneTitle The title of the milestone whose due date should be checked
	 * @return true if the given milestone is due today or past due, false otherwise
	 */
	public boolean isMilestoneDueToday(RepositoryRef repositoryRef, String milestoneTitle) {
		String url = this.baseUrl + "/repos/" + repositoryRef.getOwner() + "/" + repositoryRef.getName()
				+ "/milestones?per_page=100";
		Request request = new Request.Builder().get().url(url).build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException("Could not find milestone with title " + milestoneTitle + " for repository "
						+ repositoryRef + ". Response " + response);
			}
			List<Milestone> milestones = this.gson.fromJson(response.body().charStream(),
					new TypeToken<List<Milestone>>() {
					}.getType());
			for (Milestone milestone : milestones) {
				if (milestoneTitle.equals(milestone.getTitle())) {
					LocalDate today = LocalDate.now();
					return milestone.getDueOn() != null && today.compareTo(milestone.getDueOn().toLocalDate()) >= 0;
				}
			}
			if (milestones.size() <= 100) {
				throw new RuntimeException("Could not find open milestone with title " + milestoneTitle
						+ " for repository " + repositoryRef + " Got " + milestones);
			}
			throw new RuntimeException(
					"It is possible there are too many open milestones open (only 100 are supported). Could not find open milestone with title "
							+ milestoneTitle + " for repository " + repositoryRef + " Got " + milestones);
		}
		catch (IOException e) {
			throw new RuntimeException(
					"Could not find open milestone with title " + milestoneTitle + " for repository " + repositoryRef,
					e);
		}
	}

	/**
	 * Calculate the next release version based on the current version.
	 *
	 * The current version must conform to the pattern MAJOR.MINOR.PATCH-SNAPSHOT. If the
	 * current version is a snapshot of a patch release, then the patch release will be
	 * returned. For example, if the current version is 5.6.1-SNAPSHOT, then 5.6.1 will be
	 * returned. If the current version is a snapshot of a version that is not GA (i.e the
	 * PATCH segment is 0), then GitHub will be queried to find the next milestone or
	 * release candidate. If no pre-release versions are found, then the next version will
	 * be assumed to be the GA.
	 * @param repositoryRef The repository owner/name
	 * @param currentVersion The current project version
	 * @return the next matching milestone/release candidate or null if none exist
	 */
	public String getNextReleaseMilestone(RepositoryRef repositoryRef, String currentVersion) {
		Pattern snapshotPattern = Pattern.compile("^([0-9]+)\\.([0-9]+)\\.([0-9]+)-SNAPSHOT$");
		Matcher snapshotVersion = snapshotPattern.matcher(currentVersion);

		if (snapshotVersion.find()) {
			String patchSegment = snapshotVersion.group(3);
			String currentVersionNoIdentifier = currentVersion.replace("-SNAPSHOT", "");
			if (patchSegment.equals("0")) {
				String nextPreRelease = getNextPreRelease(repositoryRef, currentVersionNoIdentifier);
				return nextPreRelease != null ? nextPreRelease : currentVersionNoIdentifier;
			}
			else {
				return currentVersionNoIdentifier;
			}
		}
		else {
			throw new IllegalStateException(
					"Cannot calculate next release version because the current project version does not conform to the expected format");
		}
	}

	/**
	 * Calculate the next pre-release version (milestone or release candidate) based on
	 * the current version.
	 *
	 * The current version must conform to the pattern MAJOR.MINOR.PATCH. If no matching
	 * milestone or release candidate is found in GitHub then it will return null.
	 * @param repositoryRef The repository owner/name
	 * @param currentVersionNoIdentifier The current project version without any
	 * identifier
	 * @return the next matching milestone/release candidate or null if none exist
	 */
	private String getNextPreRelease(RepositoryRef repositoryRef, String currentVersionNoIdentifier) {
		String url = this.baseUrl + "/repos/" + repositoryRef.getOwner() + "/" + repositoryRef.getName()
				+ "/milestones?per_page=100";
		Request request = new Request.Builder().get().url(url).build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException(
						"Could not get milestones for repository " + repositoryRef + ". Response " + response);
			}
			List<Milestone> milestones = this.gson.fromJson(response.body().charStream(),
					new TypeToken<List<Milestone>>() {
					}.getType());
			Optional<String> nextPreRelease = milestones.stream().map(Milestone::getTitle)
					.filter(m -> m.startsWith(currentVersionNoIdentifier + "-"))
					.min((m1, m2) -> {
						Pattern preReleasePattern = Pattern.compile("^.*-([A-Z]+)([0-9]+)$");
						Matcher matcher1 = preReleasePattern.matcher(m1);
						Matcher matcher2 = preReleasePattern.matcher(m2);
						matcher1.find();
						matcher2.find();
						if (!matcher1.group(1).equals(matcher2.group(1))) {
							return m1.compareTo(m2);
						}
						else {
							return Integer.valueOf(matcher1.group(2)).compareTo(Integer.valueOf(matcher2.group(2)));
						}
					});
			return nextPreRelease.orElse(null);
		}
		catch (IOException e) {
			throw new RuntimeException("Could not find open milestones with for repository " + repositoryRef, e);
		}
	}

	/**
	 * Create a milestone.
	 *
	 * @param repository The repository owner/name
	 * @param milestone The milestone containing a title and due date
	 */
	public void createMilestone(RepositoryRef repository, Milestone milestone) {
		String url = this.baseUrl + "/repos/" + repository.getOwner() + "/" + repository.getName() + "/milestones";
		String json = this.gson.toJson(milestone);
		RequestBody body = RequestBody.create(MediaType.parse("application/json"), json);
		Request request = new Request.Builder().url(url).post(body).build();
		try {
			Response response = this.client.newCall(request).execute();
			if (!response.isSuccessful()) {
				throw new RuntimeException(String.format("Could not create milestone %s for repository %s/%s. Got response %s",
						milestone.getTitle(), repository.getOwner(), repository.getName(), response));
			}
		} catch (IOException ex) {
			throw new RuntimeException(String.format("Could not create release %s for repository %s/%s",
					milestone.getTitle(), repository.getOwner(), repository.getName()), ex);
		}
	}

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
