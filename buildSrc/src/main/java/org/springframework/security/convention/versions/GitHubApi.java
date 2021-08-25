package org.springframework.security.convention.versions;

import com.apollographql.apollo.ApolloCall;
import com.apollographql.apollo.ApolloClient;
import com.apollographql.apollo.api.Input;
import com.apollographql.apollo.api.Response;
import com.apollographql.apollo.exception.ApolloException;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.jetbrains.annotations.NotNull;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import reactor.util.retry.RetrySpec;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class GitHubApi {

	private final ApolloClient apolloClient;

	public GitHubApi(String githubToken) {
		if (githubToken == null) {
			throw new IllegalArgumentException("githubToken is required. You can set it using -PgitHubAccessToken=");
		}
		OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();
		clientBuilder.addInterceptor(new AuthorizationInterceptor(githubToken));
		this.apolloClient = ApolloClient.builder()
				.serverUrl("https://api.github.com/graphql")
				.okHttpClient(clientBuilder.build())
				.build();
	}

	public Mono<FindCreateIssueResult> findCreateIssueInput(String owner, String name, String milestone) {
		String label = "\"type: dependency-upgrade\"";
		FindCreateIssueInputQuery findCreateIssueInputQuery = new FindCreateIssueInputQuery(owner, name, Input.optional(label), Input.optional(milestone));
		return Mono.create( sink -> this.apolloClient.query(findCreateIssueInputQuery)
				.enqueue(new ApolloCall.Callback<FindCreateIssueInputQuery.Data>() {
					@Override
					public void onResponse(@NotNull Response<FindCreateIssueInputQuery.Data> response) {
						if (response.hasErrors()) {
							sink.error(new RuntimeException(response.getErrors().stream().map(e -> e.getMessage()).collect(Collectors.joining(" "))));
						} else {
							FindCreateIssueInputQuery.Data data = response.getData();
							FindCreateIssueInputQuery.Repository repository = data.repository();
							List<String> labels = repository.labels().nodes().stream().map(FindCreateIssueInputQuery.Node::id).collect(Collectors.toList());
							if (labels.isEmpty()) {
								sink.error(new IllegalArgumentException("Could not find label for " + label));
								return;
							}
							Optional<String> firstMilestoneId = repository.milestones().nodes().stream().map(FindCreateIssueInputQuery.Node1::id).findFirst();
							if (!firstMilestoneId.isPresent()) {
								sink.error(new IllegalArgumentException("Could not find OPEN milestone id for " + milestone));
								return;
							}
							String milestoneId = firstMilestoneId.get();
							String repositoryId = repository.id();
							String assigneeId = data.viewer().id();
							sink.success(new FindCreateIssueResult(repositoryId, labels, milestoneId, assigneeId));
						}
					}
					@Override
					public void onFailure(@NotNull ApolloException e) {
						sink.error(e);
					}
				}));
	}

	public static class FindCreateIssueResult {
		private final String repositoryId;
		private final List<String> labelIds;
		private final String milestoneId;
		private final String assigneeId;

		public FindCreateIssueResult(String repositoryId, List<String> labelIds, String milestoneId, String assigneeId) {
			this.repositoryId = repositoryId;
			this.labelIds = labelIds;
			this.milestoneId = milestoneId;
			this.assigneeId = assigneeId;
		}

		public String getRepositoryId() {
			return repositoryId;
		}

		public List<String> getLabelIds() {
			return labelIds;
		}

		public String getMilestoneId() {
			return milestoneId;
		}

		public String getAssigneeId() {
			return assigneeId;
		}
	}

	public Mono<RateLimitQuery.RateLimit> findRateLimit() {
		return Mono.create( sink -> this.apolloClient.query(new RateLimitQuery())
			.enqueue(new ApolloCall.Callback<RateLimitQuery.Data>() {
				@Override
				public void onResponse(@NotNull Response<RateLimitQuery.Data> response) {
					if (response.hasErrors()) {
						sink.error(new RuntimeException(response.getErrors().stream().map(e -> e.getMessage()).collect(Collectors.joining(" "))));
					} else {
						sink.success(response.getData().rateLimit());
					}
				}
				@Override
				public void onFailure(@NotNull ApolloException e) {
					sink.error(e);
				}
			}));
	}

	public Mono<Integer> createIssue(String repositoryId, String title, List<String> labelIds, String milestoneId, String assigneeId) {
		CreateIssueInputMutation createIssue = new CreateIssueInputMutation.Builder()
				.repositoryId(repositoryId)
				.title(title)
				.labelIds(labelIds)
				.milestoneId(milestoneId)
				.assigneeId(assigneeId)
				.build();
		return Mono.create( sink -> this.apolloClient.mutate(createIssue)
				.enqueue(new ApolloCall.Callback<CreateIssueInputMutation.Data>() {
					@Override
					public void onResponse(@NotNull Response<CreateIssueInputMutation.Data> response) {
						if (response.hasErrors()) {
							String message = response.getErrors().stream().map(e -> e.getMessage() + " " + e.getCustomAttributes() + " " + e.getLocations()).collect(Collectors.joining(" "));
							if (message.contains("was submitted too quickly")) {
								sink.error(new SubmittedTooQuick(message));
							} else {
								sink.error(new RuntimeException(message));
							}
						} else {
							sink.success(response.getData().createIssue().issue().number());
						}
					}
					@Override
					public void onFailure(@NotNull ApolloException e) {
						sink.error(e);
					}
				}))
				.retryWhen(
					RetrySpec.fixedDelay(3, Duration.ofMinutes(1))
						.filter(SubmittedTooQuick.class::isInstance)
						.doBeforeRetry(r -> System.out.println("Pausing for 1 minute and then retrying due to receiving \"submitted too quickly\" error from GitHub API"))
				)
				.cast(Integer.class);
	}

	public static class SubmittedTooQuick extends RuntimeException {
		public SubmittedTooQuick(String message) {
			super(message);
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
