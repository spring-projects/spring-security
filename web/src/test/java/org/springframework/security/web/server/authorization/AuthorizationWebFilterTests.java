/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.server.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class AuthorizationWebFilterTests {

	@Mock
	private ServerWebExchange exchange;

	@Mock
	private WebFilterChain chain;

	PublisherProbe<Void> chainResult = PublisherProbe.empty();

	@Test
	public void filterWhenNoSecurityContextThenThrowsAccessDenied() {
		given(this.chain.filter(this.exchange)).willReturn(this.chainResult.mono());
		AuthorizationWebFilter filter = new AuthorizationWebFilter(
				(a, e) -> Mono.error(new AccessDeniedException("Denied")));
		Mono<Void> result = filter.filter(this.exchange, this.chain);
		StepVerifier.create(result).expectError(AccessDeniedException.class).verify();
		this.chainResult.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenNoAuthenticationThenThrowsAccessDenied() {
		given(this.chain.filter(this.exchange)).willReturn(this.chainResult.mono());
		AuthorizationWebFilter filter = new AuthorizationWebFilter(
				(a, e) -> a.flatMap((auth) -> Mono.error(new AccessDeniedException("Denied"))));
		Mono<Void> result = filter.filter(this.exchange, this.chain)
			.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(new SecurityContextImpl())));
		StepVerifier.create(result).expectError(AccessDeniedException.class).verify();
		this.chainResult.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenAuthenticationThenThrowsAccessDenied() {
		given(this.chain.filter(this.exchange)).willReturn(this.chainResult.mono());
		AuthorizationWebFilter filter = new AuthorizationWebFilter(
				(a, e) -> Mono.error(new AccessDeniedException("Denied")));
		Mono<Void> result = filter.filter(this.exchange, this.chain)
			.contextWrite(
					ReactiveSecurityContextHolder.withAuthentication(new TestingAuthenticationToken("a", "b", "R")));
		StepVerifier.create(result).expectError(AccessDeniedException.class).verify();
		this.chainResult.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenDoesNotAccessAuthenticationThenSecurityContextNotSubscribed() {
		PublisherProbe<SecurityContext> context = PublisherProbe.empty();
		given(this.chain.filter(this.exchange)).willReturn(this.chainResult.mono());
		AuthorizationWebFilter filter = new AuthorizationWebFilter(
				(a, e) -> Mono.error(new AccessDeniedException("Denied")));
		Mono<Void> result = filter.filter(this.exchange, this.chain)
			.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(context.mono()));
		StepVerifier.create(result).expectError(AccessDeniedException.class).verify();
		this.chainResult.assertWasNotSubscribed();
		context.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenGrantedAndDoesNotAccessAuthenticationThenChainSubscribedAndSecurityContextNotSubscribed() {
		PublisherProbe<SecurityContext> context = PublisherProbe.empty();
		given(this.chain.filter(this.exchange)).willReturn(this.chainResult.mono());
		AuthorizationWebFilter filter = new AuthorizationWebFilter(
				(a, e) -> Mono.just(new AuthorizationDecision(true)));
		Mono<Void> result = filter.filter(this.exchange, this.chain)
			.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(context.mono()));
		StepVerifier.create(result).verifyComplete();
		this.chainResult.assertWasSubscribed();
		context.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenGrantedAndDoeAccessAuthenticationThenChainSubscribedAndSecurityContextSubscribed() {
		PublisherProbe<SecurityContext> context = PublisherProbe.empty();
		given(this.chain.filter(this.exchange)).willReturn(this.chainResult.mono());
		AuthorizationWebFilter filter = new AuthorizationWebFilter(
				(a, e) -> a.map((auth) -> (AuthorizationResult) new AuthorizationDecision(true))
					.defaultIfEmpty(new AuthorizationDecision(true)));
		Mono<Void> result = filter.filter(this.exchange, this.chain)
			.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(context.mono()));
		StepVerifier.create(result).verifyComplete();
		this.chainResult.assertWasSubscribed();
		context.assertWasSubscribed();
	}

}
