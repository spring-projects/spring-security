/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server.authentication.session;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockWebSession;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ConcurrentSessionControlServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.MaximumSessionsContext;
import org.springframework.security.web.server.authentication.ServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.SessionLimit;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ConcurrentSessionControlServerAuthenticationSuccessHandler}.
 *
 * @author Marcus da Coregio
 */
class ConcurrentSessionControlServerAuthenticationSuccessHandlerTests {

	private ConcurrentSessionControlServerAuthenticationSuccessHandler strategy;

	ReactiveSessionRegistry sessionRegistry = mock();

	ServerWebExchange exchange = mock();

	WebFilterChain chain = mock();

	ServerMaximumSessionsExceededHandler handler = mock();

	ArgumentCaptor<MaximumSessionsContext> contextCaptor = ArgumentCaptor.forClass(MaximumSessionsContext.class);

	@BeforeEach
	void setup() {
		given(this.exchange.getResponse()).willReturn(new MockServerHttpResponse());
		given(this.exchange.getRequest()).willReturn(MockServerHttpRequest.get("/").build());
		given(this.exchange.getSession()).willReturn(Mono.just(new MockWebSession()));
		given(this.handler.handle(any())).willReturn(Mono.empty());
		this.strategy = new ConcurrentSessionControlServerAuthenticationSuccessHandler(this.sessionRegistry,
				this.handler);
	}

	@Test
	void constructorWhenNullRegistryThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new ConcurrentSessionControlServerAuthenticationSuccessHandler(null, this.handler))
			.withMessage("sessionRegistry cannot be null");
	}

	@Test
	void constructorWhenNullHandlerThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(
					() -> new ConcurrentSessionControlServerAuthenticationSuccessHandler(this.sessionRegistry, null))
			.withMessage("maximumSessionsExceededHandler cannot be null");
	}

	@Test
	void setMaximumSessionsForAuthenticationWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.strategy.setSessionLimit(null))
			.withMessage("sessionLimit cannot be null");
	}

	@Test
	void onAuthenticationWhenSessionLimitIsUnlimitedThenDoNothing() {
		ServerMaximumSessionsExceededHandler handler = mock(ServerMaximumSessionsExceededHandler.class);
		this.strategy = new ConcurrentSessionControlServerAuthenticationSuccessHandler(this.sessionRegistry, handler);
		this.strategy.setSessionLimit(SessionLimit.UNLIMITED);
		this.strategy.onAuthenticationSuccess(null, TestAuthentication.authenticatedUser()).block();
		verifyNoInteractions(handler, this.sessionRegistry);
	}

	@Test
	void onAuthenticationWhenMaximumSessionsIsOneAndExceededThenHandlerIsCalled() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		List<ReactiveSessionInformation> sessions = Arrays.asList(createSessionInformation("100"),
				createSessionInformation("101"));
		given(this.sessionRegistry.getAllSessions(authentication.getPrincipal()))
			.willReturn(Flux.fromIterable(sessions));
		this.strategy.onAuthenticationSuccess(new WebFilterExchange(this.exchange, this.chain), authentication).block();
		verify(this.handler).handle(this.contextCaptor.capture());
		assertThat(this.contextCaptor.getValue().getMaximumSessionsAllowed()).isEqualTo(1);
		assertThat(this.contextCaptor.getValue().getSessions()).isEqualTo(sessions);
		assertThat(this.contextCaptor.getValue().getAuthentication()).isEqualTo(authentication);
	}

	@Test
	void onAuthenticationWhenMaximumSessionsIsGreaterThanOneAndExceededThenHandlerIsCalled() {
		this.strategy.setSessionLimit(SessionLimit.of(5));
		Authentication authentication = TestAuthentication.authenticatedUser();
		List<ReactiveSessionInformation> sessions = Arrays.asList(createSessionInformation("100"),
				createSessionInformation("101"), createSessionInformation("102"), createSessionInformation("103"),
				createSessionInformation("104"));
		given(this.sessionRegistry.getAllSessions(authentication.getPrincipal()))
			.willReturn(Flux.fromIterable(sessions));
		this.strategy.onAuthenticationSuccess(new WebFilterExchange(this.exchange, this.chain), authentication).block();
		verify(this.handler).handle(this.contextCaptor.capture());
		assertThat(this.contextCaptor.getValue().getMaximumSessionsAllowed()).isEqualTo(5);
		assertThat(this.contextCaptor.getValue().getSessions()).isEqualTo(sessions);
		assertThat(this.contextCaptor.getValue().getAuthentication()).isEqualTo(authentication);
	}

	@Test
	void onAuthenticationWhenMaximumSessionsForUsersAreDifferentThenHandlerIsCalledWhereNeeded() {
		Authentication user = TestAuthentication.authenticatedUser();
		Authentication admin = TestAuthentication.authenticatedAdmin();
		this.strategy.setSessionLimit((authentication) -> {
			if (authentication.equals(user)) {
				return Mono.just(1);
			}
			return Mono.just(3);
		});

		List<ReactiveSessionInformation> userSessions = Arrays.asList(createSessionInformation("100"));
		List<ReactiveSessionInformation> adminSessions = Arrays.asList(createSessionInformation("200"),
				createSessionInformation("201"));

		given(this.sessionRegistry.getAllSessions(user.getPrincipal())).willReturn(Flux.fromIterable(userSessions));
		given(this.sessionRegistry.getAllSessions(admin.getPrincipal())).willReturn(Flux.fromIterable(adminSessions));

		this.strategy.onAuthenticationSuccess(new WebFilterExchange(this.exchange, this.chain), user).block();
		this.strategy.onAuthenticationSuccess(new WebFilterExchange(this.exchange, this.chain), admin).block();
		verify(this.handler).handle(this.contextCaptor.capture());
		assertThat(this.contextCaptor.getValue().getMaximumSessionsAllowed()).isEqualTo(1);
		assertThat(this.contextCaptor.getValue().getSessions()).isEqualTo(userSessions);
		assertThat(this.contextCaptor.getValue().getAuthentication()).isEqualTo(user);
	}

	private ReactiveSessionInformation createSessionInformation(String sessionId) {
		return new ReactiveSessionInformation(sessionId, "principal", Instant.now());
	}

}
