/*
 * Copyright 2002-2022 the original author or authors.
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

import java.security.Principal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @author César Revert
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class ExceptionTranslationWebFilterTests {

	@Mock
	private Principal principal;

	@Mock
	private AnonymousAuthenticationToken anonymousPrincipal;

	@Mock
	private ServerWebExchange exchange;

	@Mock
	private WebFilterChain chain;

	@Mock
	private ServerAccessDeniedHandler deniedHandler;

	@Mock
	private ServerAuthenticationEntryPoint entryPoint;

	private PublisherProbe<Void> deniedPublisher = PublisherProbe.empty();

	private PublisherProbe<Void> entryPointPublisher = PublisherProbe.empty();

	private ExceptionTranslationWebFilter filter = new ExceptionTranslationWebFilter();

	@BeforeEach
	public void setup() {
		this.filter.setAuthenticationEntryPoint(this.entryPoint);
		this.filter.setAccessDeniedHandler(this.deniedHandler);
	}

	@Test
	public void filterWhenNoExceptionThenNotHandled() {
		given(this.chain.filter(this.exchange)).willReturn(Mono.empty());
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).expectComplete().verify();
		this.deniedPublisher.assertWasNotSubscribed();
		this.entryPointPublisher.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenNotAccessDeniedExceptionThenNotHandled() {
		given(this.chain.filter(this.exchange)).willReturn(Mono.error(new IllegalArgumentException("oops")));
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).expectError(IllegalArgumentException.class)
				.verify();
		this.deniedPublisher.assertWasNotSubscribed();
		this.entryPointPublisher.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenAccessDeniedExceptionAndNotAuthenticatedThenHandled() {
		given(this.entryPoint.commence(any(), any())).willReturn(this.entryPointPublisher.mono());
		given(this.exchange.getPrincipal()).willReturn(Mono.empty());
		given(this.chain.filter(this.exchange)).willReturn(Mono.error(new AccessDeniedException("Not Authorized")));
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).verifyComplete();
		this.deniedPublisher.assertWasNotSubscribed();
		this.entryPointPublisher.assertWasSubscribed();
	}

	@Test
	public void filterWhenDefaultsAndAccessDeniedExceptionAndAuthenticatedThenForbidden() {
		given(this.exchange.getResponse()).willReturn(new MockServerHttpResponse());
		this.filter = new ExceptionTranslationWebFilter();
		given(this.exchange.getPrincipal()).willReturn(Mono.just(this.principal));
		given(this.chain.filter(this.exchange)).willReturn(Mono.error(new AccessDeniedException("Not Authorized")));
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).expectComplete().verify();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	public void filterWhenDefaultsAndAccessDeniedExceptionAndNotAuthenticatedThenUnauthorized() {
		given(this.exchange.getResponse()).willReturn(new MockServerHttpResponse());
		this.filter = new ExceptionTranslationWebFilter();
		given(this.exchange.getPrincipal()).willReturn(Mono.empty());
		given(this.chain.filter(this.exchange)).willReturn(Mono.error(new AccessDeniedException("Not Authorized")));
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).expectComplete().verify();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void filterWhenAccessDeniedExceptionAndAuthenticatedThenHandled() {
		given(this.deniedHandler.handle(any(), any())).willReturn(this.deniedPublisher.mono());
		given(this.entryPoint.commence(any(), any())).willReturn(this.entryPointPublisher.mono());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(this.principal));
		given(this.chain.filter(this.exchange)).willReturn(Mono.error(new AccessDeniedException("Not Authorized")));
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).expectComplete().verify();
		this.deniedPublisher.assertWasSubscribed();
		this.entryPointPublisher.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenAccessDeniedExceptionAndAnonymousAuthenticatedThenHandled() {
		given(this.entryPoint.commence(any(), any())).willReturn(this.entryPointPublisher.mono());
		given(this.exchange.getPrincipal()).willReturn(Mono.just(this.anonymousPrincipal));
		given(this.chain.filter(this.exchange)).willReturn(Mono.error(new AccessDeniedException("Not Authorized")));
		StepVerifier.create(this.filter.filter(this.exchange, this.chain)).expectComplete().verify();
		this.deniedPublisher.assertWasNotSubscribed();
		this.entryPointPublisher.assertWasSubscribed();
	}

	@Test
	public void setAccessDeniedHandlerWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAccessDeniedHandler(null));
	}

	@Test
	public void setAuthenticationEntryPointWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationEntryPoint(null));
	}

	@Test
	public void setAuthenticationTrustResolver() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationTrustResolver(null));
	}

}
