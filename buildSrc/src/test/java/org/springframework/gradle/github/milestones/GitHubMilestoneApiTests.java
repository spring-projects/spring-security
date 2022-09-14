package org.springframework.gradle.github.milestones;

import java.nio.charset.Charset;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
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


public class GitHubMilestoneApiTests {
	private GitHubMilestoneApi github;

	private RepositoryRef repositoryRef = RepositoryRef.owner("spring-projects").repository("spring-security").build();

	private MockWebServer server;

	private String baseUrl;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.github = new GitHubMilestoneApi("mock-oauth-token");
		this.baseUrl = this.server.url("/api").toString();
		this.github.setBaseUrl(this.baseUrl);
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void findMilestoneNumberByTitleWhenFoundThenSuccess() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"2021-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		long milestoneNumberByTitle = this.github.findMilestoneNumberByTitle(this.repositoryRef, "5.5.0-RC1");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(milestoneNumberByTitle).isEqualTo(191);
	}

	@Test
	public void findMilestoneNumberByTitleWhenNotFoundThenException() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"2021-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.github.findMilestoneNumberByTitle(this.repositoryRef, "missing"));
	}

	@Test
	public void isOpenIssuesForMilestoneNumberWhenAllClosedThenFalse() throws Exception {
		String responseJson = "[]";
		long milestoneNumber = 202;
		this.server.enqueue(new MockResponse().setBody(responseJson));

		assertThat(this.github.isOpenIssuesForMilestoneNumber(this.repositoryRef, milestoneNumber)).isFalse();

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/issues?per_page=1&milestone=" + milestoneNumber);
	}

	@Test
	public void isOpenIssuesForMilestoneNumberWhenOpenIssuesThenTrue() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/issues/9562\",\n" +
				"      \"repository_url\":\"https://api.github.com/repos/spring-projects/spring-security\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/issues/9562/labels{/name}\",\n" +
				"      \"comments_url\":\"https://api.github.com/repos/spring-projects/spring-security/issues/9562/comments\",\n" +
				"      \"events_url\":\"https://api.github.com/repos/spring-projects/spring-security/issues/9562/events\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/pull/9562\",\n" +
				"      \"id\":851886504,\n" +
				"      \"node_id\":\"MDExOlB1bGxSZXF1ZXN0NjEwMjMzMDcw\",\n" +
				"      \"number\":9562,\n" +
				"      \"title\":\"Add package-list\",\n" +
				"      \"user\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"labels\":[\n" +
				"         {\n" +
				"            \"id\":322225043,\n" +
				"            \"node_id\":\"MDU6TGFiZWwzMjIyMjUwNDM=\",\n" +
				"            \"url\":\"https://api.github.com/repos/spring-projects/spring-security/labels/in:%20build\",\n" +
				"            \"name\":\"in: build\",\n" +
				"            \"color\":\"e8f9de\",\n" +
				"            \"default\":false,\n" +
				"            \"description\":\"An issue in the build\"\n" +
				"         },\n" +
				"         {\n" +
				"            \"id\":322225079,\n" +
				"            \"node_id\":\"MDU6TGFiZWwzMjIyMjUwNzk=\",\n" +
				"            \"url\":\"https://api.github.com/repos/spring-projects/spring-security/labels/type:%20bug\",\n" +
				"            \"name\":\"type: bug\",\n" +
				"            \"color\":\"e3d9fc\",\n" +
				"            \"default\":false,\n" +
				"            \"description\":\"A general bug\"\n" +
				"         }\n" +
				"      ],\n" +
				"      \"state\":\"open\",\n" +
				"      \"locked\":false,\n" +
				"      \"assignee\":{\n" +
				"         \"login\":\"rwinch\",\n" +
				"         \"id\":362503,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjUwMw==\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/362503?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/rwinch\",\n" +
				"         \"html_url\":\"https://github.com/rwinch\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/rwinch/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/rwinch/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/rwinch/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/rwinch/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/rwinch/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/rwinch/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/rwinch/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/rwinch/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/rwinch/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"assignees\":[\n" +
				"         {\n" +
				"            \"login\":\"rwinch\",\n" +
				"            \"id\":362503,\n" +
				"            \"node_id\":\"MDQ6VXNlcjM2MjUwMw==\",\n" +
				"            \"avatar_url\":\"https://avatars.githubusercontent.com/u/362503?v=4\",\n" +
				"            \"gravatar_id\":\"\",\n" +
				"            \"url\":\"https://api.github.com/users/rwinch\",\n" +
				"            \"html_url\":\"https://github.com/rwinch\",\n" +
				"            \"followers_url\":\"https://api.github.com/users/rwinch/followers\",\n" +
				"            \"following_url\":\"https://api.github.com/users/rwinch/following{/other_user}\",\n" +
				"            \"gists_url\":\"https://api.github.com/users/rwinch/gists{/gist_id}\",\n" +
				"            \"starred_url\":\"https://api.github.com/users/rwinch/starred{/owner}{/repo}\",\n" +
				"            \"subscriptions_url\":\"https://api.github.com/users/rwinch/subscriptions\",\n" +
				"            \"organizations_url\":\"https://api.github.com/users/rwinch/orgs\",\n" +
				"            \"repos_url\":\"https://api.github.com/users/rwinch/repos\",\n" +
				"            \"events_url\":\"https://api.github.com/users/rwinch/events{/privacy}\",\n" +
				"            \"received_events_url\":\"https://api.github.com/users/rwinch/received_events\",\n" +
				"            \"type\":\"User\",\n" +
				"            \"site_admin\":false\n" +
				"         }\n" +
				"      ],\n" +
				"      \"milestone\":{\n" +
				"         \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"         \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"         \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"         \"id\":5884208,\n" +
				"         \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"         \"number\":191,\n" +
				"         \"title\":\"5.5.0-RC1\",\n" +
				"         \"description\":\"\",\n" +
				"         \"creator\":{\n" +
				"            \"login\":\"jzheaux\",\n" +
				"            \"id\":3627351,\n" +
				"            \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"            \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"            \"gravatar_id\":\"\",\n" +
				"            \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"            \"html_url\":\"https://github.com/jzheaux\",\n" +
				"            \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"            \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"            \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"            \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"            \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"            \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"            \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"            \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"            \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"            \"type\":\"User\",\n" +
				"            \"site_admin\":false\n" +
				"         },\n" +
				"         \"open_issues\":21,\n" +
				"         \"closed_issues\":23,\n" +
				"         \"state\":\"open\",\n" +
				"         \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"         \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"         \"due_on\":\"2021-04-12T07:00:00Z\",\n" +
				"         \"closed_at\":null\n" +
				"      },\n" +
				"      \"comments\":0,\n" +
				"      \"created_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"updated_at\":\"2021-04-07T17:00:00Z\",\n" +
				"      \"closed_at\":null,\n" +
				"      \"author_association\":\"MEMBER\",\n" +
				"      \"active_lock_reason\":null,\n" +
				"      \"pull_request\":{\n" +
				"         \"url\":\"https://api.github.com/repos/spring-projects/spring-security/pulls/9562\",\n" +
				"         \"html_url\":\"https://github.com/spring-projects/spring-security/pull/9562\",\n" +
				"         \"diff_url\":\"https://github.com/spring-projects/spring-security/pull/9562.diff\",\n" +
				"         \"patch_url\":\"https://github.com/spring-projects/spring-security/pull/9562.patch\"\n" +
				"      },\n" +
				"      \"body\":\"Closes gh-9528\\r\\n\\r\\n<!--\\r\\nFor Security Vulnerabilities, please use https://pivotal.io/security#reporting\\r\\n-->\\r\\n\\r\\n<!--\\r\\nBefore creating new features, we recommend creating an issue to discuss the feature. This ensures that everyone is on the same page before extensive work is done.\\r\\n\\r\\nThanks for contributing to Spring Security. Please provide a brief description of your pull-request and reference any related issue numbers (prefix references with gh-).\\r\\n-->\\r\\n\",\n" +
				"      \"performed_via_github_app\":null\n" +
				"   }\n" +
				"]";
		long milestoneNumber = 191;
		this.server.enqueue(new MockResponse().setBody(responseJson));

		assertThat(this.github.isOpenIssuesForMilestoneNumber(this.repositoryRef, milestoneNumber)).isTrue();

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/issues?per_page=1&milestone=" + milestoneNumber);
	}

	@Test
	public void isMilestoneDueTodayWhenNotFoundThenException() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"2021-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.github.isMilestoneDueToday(this.repositoryRef, "missing"));
	}

	@Test
	public void isMilestoneDueTodayWhenPastDueThenTrue() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"2021-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		boolean dueToday = this.github.isMilestoneDueToday(this.repositoryRef, "5.5.0-RC1");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(dueToday).isTrue();
	}

	@Test
	public void isMilestoneDueTodayWhenDueTodayThenTrue() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"" + LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant().toString() + "\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		boolean dueToday = this.github.isMilestoneDueToday(this.repositoryRef, "5.5.0-RC1");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(dueToday).isTrue();
	}

	@Test
	public void isMilestoneDueTodayWhenNoDueDateThenFalse() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		boolean dueToday = this.github.isMilestoneDueToday(this.repositoryRef, "5.5.0-RC1");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(dueToday).isFalse();
	}

	@Test
	public void isMilestoneDueTodayWhenDueDateInFutureThenFalse() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"3000-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		boolean dueToday = this.github.isMilestoneDueToday(this.repositoryRef, "5.5.0-RC1");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(dueToday).isFalse();
	}

	@Test
	public void calculateNextReleaseMilestoneWhenCurrentVersionIsNotSnapshotThenException() {
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.github.getNextReleaseMilestone(this.repositoryRef, "5.5.0-RC1"));
	}

	@Test
	public void calculateNextReleaseMilestoneWhenPatchSegmentGreaterThan0ThenReturnsVersionWithoutSnapshot() {
		String nextVersion = this.github.getNextReleaseMilestone(this.repositoryRef, "5.5.1-SNAPSHOT");

		assertThat(nextVersion).isEqualTo("5.5.1");
	}

	@Test
	public void calculateNextReleaseMilestoneWhenMilestoneAndRcExistThenReturnsMilestone() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.5.0-M1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC1\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"3000-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		String nextVersion = this.github.getNextReleaseMilestone(this.repositoryRef, "5.5.0-SNAPSHOT");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(nextVersion).isEqualTo("5.5.0-M1");
	}

	@Test
	public void calculateNextReleaseMilestoneWhenTwoMilestonesExistThenReturnsSmallerMilestone() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.5.0-M9\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-M10\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"3000-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		String nextVersion = this.github.getNextReleaseMilestone(this.repositoryRef, "5.5.0-SNAPSHOT");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(nextVersion).isEqualTo("5.5.0-M9");
	}

	@Test
	public void calculateNextReleaseMilestoneWhenTwoRcsExistThenReturnsSmallerRc() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.5.0-RC9\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.5.0-RC10\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"3000-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		String nextVersion = this.github.getNextReleaseMilestone(this.repositoryRef, "5.5.0-SNAPSHOT");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(nextVersion).isEqualTo("5.5.0-RC9");
	}

	@Test
	public void calculateNextReleaseMilestoneWhenNoPreReleaseThenReturnsVersionWithoutSnapshot() throws Exception {
		String responseJson = "[\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/207\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/207/labels\",\n" +
				"      \"id\":6611880,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNjYxMTg4MA==\",\n" +
				"      \"number\":207,\n" +
				"      \"title\":\"5.6.x\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jgrandja\",\n" +
				"         \"id\":10884212,\n" +
				"         \"node_id\":\"MDQ6VXNlcjEwODg0MjEy\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/10884212?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jgrandja\",\n" +
				"         \"html_url\":\"https://github.com/jgrandja\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jgrandja/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jgrandja/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jgrandja/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jgrandja/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jgrandja/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jgrandja/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jgrandja/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jgrandja/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jgrandja/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":1,\n" +
				"      \"closed_issues\":0,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2021-03-31T11:29:17Z\",\n" +
				"      \"updated_at\":\"2021-03-31T11:30:47Z\",\n" +
				"      \"due_on\":null,\n" +
				"      \"closed_at\":null\n" +
				"   },\n" +
				"   {\n" +
				"      \"url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191\",\n" +
				"      \"html_url\":\"https://github.com/spring-projects/spring-security/milestone/191\",\n" +
				"      \"labels_url\":\"https://api.github.com/repos/spring-projects/spring-security/milestones/191/labels\",\n" +
				"      \"id\":5884208,\n" +
				"      \"node_id\":\"MDk6TWlsZXN0b25lNTg4NDIwOA==\",\n" +
				"      \"number\":191,\n" +
				"      \"title\":\"5.4.3\",\n" +
				"      \"description\":\"\",\n" +
				"      \"creator\":{\n" +
				"         \"login\":\"jzheaux\",\n" +
				"         \"id\":3627351,\n" +
				"         \"node_id\":\"MDQ6VXNlcjM2MjczNTE=\",\n" +
				"         \"avatar_url\":\"https://avatars.githubusercontent.com/u/3627351?v=4\",\n" +
				"         \"gravatar_id\":\"\",\n" +
				"         \"url\":\"https://api.github.com/users/jzheaux\",\n" +
				"         \"html_url\":\"https://github.com/jzheaux\",\n" +
				"         \"followers_url\":\"https://api.github.com/users/jzheaux/followers\",\n" +
				"         \"following_url\":\"https://api.github.com/users/jzheaux/following{/other_user}\",\n" +
				"         \"gists_url\":\"https://api.github.com/users/jzheaux/gists{/gist_id}\",\n" +
				"         \"starred_url\":\"https://api.github.com/users/jzheaux/starred{/owner}{/repo}\",\n" +
				"         \"subscriptions_url\":\"https://api.github.com/users/jzheaux/subscriptions\",\n" +
				"         \"organizations_url\":\"https://api.github.com/users/jzheaux/orgs\",\n" +
				"         \"repos_url\":\"https://api.github.com/users/jzheaux/repos\",\n" +
				"         \"events_url\":\"https://api.github.com/users/jzheaux/events{/privacy}\",\n" +
				"         \"received_events_url\":\"https://api.github.com/users/jzheaux/received_events\",\n" +
				"         \"type\":\"User\",\n" +
				"         \"site_admin\":false\n" +
				"      },\n" +
				"      \"open_issues\":21,\n" +
				"      \"closed_issues\":23,\n" +
				"      \"state\":\"open\",\n" +
				"      \"created_at\":\"2020-09-16T13:28:03Z\",\n" +
				"      \"updated_at\":\"2021-04-06T23:47:10Z\",\n" +
				"      \"due_on\":\"2021-04-12T07:00:00Z\",\n" +
				"      \"closed_at\":null\n" +
				"   }\n" +
				"]";
		this.server.enqueue(new MockResponse().setBody(responseJson));

		String nextVersion = this.github.getNextReleaseMilestone(this.repositoryRef, "5.5.0-SNAPSHOT");

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("get");
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones?per_page=100");

		assertThat(nextVersion).isEqualTo("5.5.0");
	}

	@Test
	public void createMilestoneWhenValidParametersThenSuccess() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(204));
		Milestone milestone = new Milestone();
		milestone.setTitle("1.0.0");
		milestone.setDueOn(LocalDate.of(2022, 5, 4).atTime(LocalTime.NOON));
		this.github.createMilestone(this.repositoryRef, milestone);

		RecordedRequest recordedRequest = this.server.takeRequest(1, TimeUnit.SECONDS);
		assertThat(recordedRequest.getMethod()).isEqualToIgnoringCase("post");
		assertThat(recordedRequest.getRequestUrl().toString())
				.isEqualTo(this.baseUrl + "/repos/spring-projects/spring-security/milestones");
		assertThat(recordedRequest.getBody().readString(Charset.defaultCharset()))
				.isEqualTo("{\"title\":\"1.0.0\",\"due_on\":\"2022-05-04T12:00:00Z\"}");
	}

	@Test
	public void createMilestoneWhenErrorResponseThenException() throws Exception {
		this.server.enqueue(new MockResponse().setResponseCode(400));
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.github.createMilestone(this.repositoryRef, new Milestone()));
	}

}
