/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.server.csrf;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.mock.web.server.MockServerWebExchange.from;
import static org.springframework.web.reactive.function.BodyInserters.fromMultipartData;

/**
 * @author Rob Winch
 * @author Parikshit Dutta
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class CsrfWebFilterTests {

	@Mock
	private WebFilterChain chain;

	@Mock
	private ServerCsrfTokenRepository repository;

	private CsrfToken token = new DefaultCsrfToken("csrf", "CSRF", "a");

	private CsrfWebFilter csrfFilter = new CsrfWebFilter();

	private MockServerWebExchange get = from(MockServerHttpRequest.get("/"));

	private ServerWebExchange post = from(MockServerHttpRequest.post("/"));

	@Test
	public void filterWhenGetThenSessionNotCreatedAndChainContinues() {
		PublisherProbe<Void> chainResult = PublisherProbe.empty();
		when(this.chain.filter(this.get)).thenReturn(chainResult.mono());

		Mono<Void> result = this.csrfFilter.filter(this.get, this.chain);

		StepVerifier.create(result).verifyComplete();

		Mono<Boolean> isSessionStarted = this.get.getSession().map(WebSession::isStarted);
		StepVerifier.create(isSessionStarted).expectNext(false).verifyComplete();

		chainResult.assertWasSubscribed();
	}

	@Test
	public void filterWhenPostAndNoTokenThenCsrfException() {
		Mono<Void> result = this.csrfFilter.filter(this.post, this.chain);

		StepVerifier.create(result).verifyComplete();

		assertThat(this.post.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void filterWhenPostAndEstablishedCsrfTokenAndRequestMissingTokenThenCsrfException() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));

		Mono<Void> result = this.csrfFilter.filter(this.post, this.chain);

		StepVerifier.create(result).verifyComplete();

		assertThat(this.post.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void filterWhenPostAndEstablishedCsrfTokenAndRequestParamInvalidTokenThenCsrfException() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));
		this.post = from(MockServerHttpRequest.post("/")
				.body(this.token.getParameterName() + "=" + this.token.getToken() + "INVALID"));

		Mono<Void> result = this.csrfFilter.filter(this.post, this.chain);

		StepVerifier.create(result).verifyComplete();

		assertThat(this.post.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void filterWhenPostAndEstablishedCsrfTokenAndRequestParamValidTokenThenContinues() {
		PublisherProbe<Void> chainResult = PublisherProbe.empty();
		when(this.chain.filter(any())).thenReturn(chainResult.mono());

		this.csrfFilter.setCsrfTokenRepository(this.repository);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));
		when(this.repository.generateToken(any())).thenReturn(Mono.just(this.token));
		this.post = from(MockServerHttpRequest.post("/").contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(this.token.getParameterName() + "=" + this.token.getToken()));

		Mono<Void> result = this.csrfFilter.filter(this.post, this.chain);

		StepVerifier.create(result).verifyComplete();

		chainResult.assertWasSubscribed();
	}

	@Test
	public void filterWhenPostAndEstablishedCsrfTokenAndHeaderInvalidTokenThenCsrfException() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));
		this.post = from(
				MockServerHttpRequest.post("/").header(this.token.getHeaderName(), this.token.getToken() + "INVALID"));

		Mono<Void> result = this.csrfFilter.filter(this.post, this.chain);

		StepVerifier.create(result).verifyComplete();

		assertThat(this.post.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void filterWhenPostAndEstablishedCsrfTokenAndHeaderValidTokenThenContinues() {
		PublisherProbe<Void> chainResult = PublisherProbe.empty();
		when(this.chain.filter(any())).thenReturn(chainResult.mono());

		this.csrfFilter.setCsrfTokenRepository(this.repository);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));
		when(this.repository.generateToken(any())).thenReturn(Mono.just(this.token));
		this.post = from(MockServerHttpRequest.post("/").header(this.token.getHeaderName(), this.token.getToken()));

		Mono<Void> result = this.csrfFilter.filter(this.post, this.chain);

		StepVerifier.create(result).verifyComplete();

		chainResult.assertWasSubscribed();
	}

	@Test
	// gh-8452
	public void matchesRequireCsrfProtectionWhenNonStandardHTTPMethodIsUsed() {
		MockServerWebExchange nonStandardHttpExchange = from(
				MockServerHttpRequest.method("non-standard-http-method", "/"));

		ServerWebExchangeMatcher serverWebExchangeMatcher = CsrfWebFilter.DEFAULT_CSRF_MATCHER;
		assertThat(serverWebExchangeMatcher.matches(nonStandardHttpExchange).map(MatchResult::isMatch).block())
				.isTrue();
	}

	@Test
	public void doFilterWhenSkipExchangeInvokedThenSkips() {
		PublisherProbe<Void> chainResult = PublisherProbe.empty();
		when(this.chain.filter(any())).thenReturn(chainResult.mono());

		ServerWebExchangeMatcher matcher = mock(ServerWebExchangeMatcher.class);
		this.csrfFilter.setRequireCsrfProtectionMatcher(matcher);

		MockServerWebExchange exchange = from(MockServerHttpRequest.post("/post").build());
		CsrfWebFilter.skipExchange(exchange);
		this.csrfFilter.filter(exchange, this.chain).block();

		verifyZeroInteractions(matcher);
	}

	@Test
	public void filterWhenMultipartFormDataAndNotEnabledThenDenied() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));

		WebTestClient client = WebTestClient.bindToController(new OkController()).webFilter(this.csrfFilter).build();

		client.post().uri("/").contentType(MediaType.MULTIPART_FORM_DATA)
				.body(fromMultipartData(this.token.getParameterName(), this.token.getToken())).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	public void filterWhenMultipartFormDataAndEnabledThenGranted() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		this.csrfFilter.setTokenFromMultipartDataEnabled(true);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));
		when(this.repository.generateToken(any())).thenReturn(Mono.just(this.token));

		WebTestClient client = WebTestClient.bindToController(new OkController()).webFilter(this.csrfFilter).build();

		client.post().uri("/").contentType(MediaType.MULTIPART_FORM_DATA)
				.body(fromMultipartData(this.token.getParameterName(), this.token.getToken())).exchange().expectStatus()
				.is2xxSuccessful();
	}

	@Test
	public void filterWhenFormDataAndEnabledThenGranted() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		this.csrfFilter.setTokenFromMultipartDataEnabled(true);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));
		when(this.repository.generateToken(any())).thenReturn(Mono.just(this.token));

		WebTestClient client = WebTestClient.bindToController(new OkController()).webFilter(this.csrfFilter).build();

		client.post().uri("/").contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.bodyValue(this.token.getParameterName() + "=" + this.token.getToken()).exchange().expectStatus()
				.is2xxSuccessful();
	}

	@Test
	public void filterWhenMultipartMixedAndEnabledThenNotRead() {
		this.csrfFilter.setCsrfTokenRepository(this.repository);
		this.csrfFilter.setTokenFromMultipartDataEnabled(true);
		when(this.repository.loadToken(any())).thenReturn(Mono.just(this.token));

		WebTestClient client = WebTestClient.bindToController(new OkController()).webFilter(this.csrfFilter).build();

		client.post().uri("/").contentType(MediaType.MULTIPART_MIXED)
				.bodyValue(this.token.getParameterName() + "=" + this.token.getToken()).exchange().expectStatus()
				.isForbidden();
	}

	@RestController
	static class OkController {

		@RequestMapping("/**")
		String ok() {
			return "ok";
		}

	}

}
