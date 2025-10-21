/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.server.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.NonBuildableAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.authentication.DefaultEqualsGrantedAuthority;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @author Rafiullah Hamedy
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticationWebFilterTests {

	@Mock
	private ServerAuthenticationSuccessHandler successHandler;

	@Mock
	private ServerAuthenticationConverter authenticationConverter;

	@Mock
	private ReactiveAuthenticationManager authenticationManager;

	@Mock
	private ServerAuthenticationFailureHandler failureHandler;

	@Mock
	private ServerSecurityContextRepository securityContextRepository;

	@Mock
	private ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver;

	private AuthenticationWebFilter filter;

	@BeforeEach
	public void setup() {
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		this.filter.setAuthenticationSuccessHandler(this.successHandler);
		this.filter.setServerAuthenticationConverter(this.authenticationConverter);
		this.filter.setSecurityContextRepository(this.securityContextRepository);
		this.filter.setAuthenticationFailureHandler(this.failureHandler);
	}

	@Test
	public void filterWhenDefaultsAndNoAuthenticationThenContinues() {
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();
		verifyNoMoreInteractions(this.authenticationManager);
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndNoAuthenticationThenContinues() {
		this.filter = new AuthenticationWebFilter(this.authenticationManagerResolver);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();
		verifyNoMoreInteractions(this.authenticationManagerResolver);
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationSuccessThenContinues() {
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.just(new TestingAuthenticationToken("test", "this", "ROLE")));
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationSuccessThenContinues() {
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.just(new TestingAuthenticationToken("test", "this", "ROLE")));
		given(this.authenticationManagerResolver.resolve(any())).willReturn(Mono.just(this.authenticationManager));
		this.filter = new AuthenticationWebFilter(this.authenticationManagerResolver);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationFailThenUnauthorized() {
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.error(new BadCredentialsException("failed")));
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<Void> result = client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isUnauthorized()
			.expectHeader()
			.valueMatches("WWW-Authenticate", "Basic realm=\"Realm\"")
			.expectBody()
			.isEmpty();
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenAuthenticatedThenCombinesAuthorities() {
		String ROLE_EXISTING = "ROLE_EXISTING";
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				ROLE_EXISTING);
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.just(new TestingAuthenticationToken("user", "password", "TEST")));
		given(this.securityContextRepository.save(any(), any())).willReturn(Mono.empty());
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		this.filter.setSecurityContextRepository(this.securityContextRepository);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(new RunAsWebFilter(existingAuthn), this.filter)
			.build();
		client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isOk();
		ArgumentCaptor<SecurityContext> context = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.securityContextRepository).save(any(), context.capture());
		Authentication authentication = context.getValue().getAuthentication();
		assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder(ROLE_EXISTING, "TEST");
	}

	/**
	 * This is critical to avoid adding duplicate GrantedAuthority instances with the
	 * same' authority when the issuedAt is too old and a new instance is requested.
	 * @throws Exception
	 */
	@Test
	public void filterWhenDefaultEqualsAuthorityThenNoDuplicates() {
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				new DefaultEqualsGrantedAuthority());
		given(this.authenticationManager.authenticate(any())).willReturn(
				Mono.just(new TestingAuthenticationToken("user", "password", new DefaultEqualsGrantedAuthority())));
		given(this.securityContextRepository.save(any(), any())).willReturn(Mono.empty());
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		this.filter.setSecurityContextRepository(this.securityContextRepository);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(new RunAsWebFilter(existingAuthn), this.filter)
			.build();
		client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isOk();
		ArgumentCaptor<SecurityContext> context = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.securityContextRepository).save(any(), context.capture());
		Authentication authentication = context.getValue().getAuthentication();
		assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactly(DefaultEqualsGrantedAuthority.AUTHORITY);
	}

	@Test
	void doFilterWhenNotOverridingToBuilderThenDoesNotMergeAuthorities() throws Exception {
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password", "FACTORONE");
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.just(new NonBuildableAuthenticationToken("user", "password", "FACTORTWO")));
		given(this.securityContextRepository.save(any(), any())).willReturn(Mono.empty());
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		this.filter.setSecurityContextRepository(this.securityContextRepository);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(new RunAsWebFilter(existingAuthn), this.filter)
			.build();
		client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isOk();
		ArgumentCaptor<SecurityContext> context = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.securityContextRepository).save(any(), context.capture());
		Authentication authentication = context.getValue().getAuthentication();
		SecurityAssertions.assertThat(authentication)
			.authorities()
			.extracting(GrantedAuthority::getAuthority)
			.containsExactly("FACTORTWO");
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationFailThenUnauthorized() {
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.error(new BadCredentialsException("failed")));
		given(this.authenticationManagerResolver.resolve(any())).willReturn(Mono.just(this.authenticationManager));
		this.filter = new AuthenticationWebFilter(this.authenticationManagerResolver);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<Void> result = client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isUnauthorized()
			.expectHeader()
			.valueMatches("WWW-Authenticate", "Basic realm=\"Realm\"")
			.expectBody()
			.isEmpty();
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenConvertEmptyThenOk() {
		given(this.authenticationConverter.convert(any())).willReturn(Mono.empty());
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		client.get()
			.uri("/")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();
		verify(this.securityContextRepository, never()).save(any(), any());
		verifyNoMoreInteractions(this.authenticationManager, this.successHandler, this.failureHandler);
	}

	@Test
	public void filterWhenConvertErrorThenServerError() {
		given(this.authenticationConverter.convert(any())).willReturn(Mono.error(new RuntimeException("Unexpected")));
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		client.get().uri("/").exchange().expectStatus().is5xxServerError().expectBody().isEmpty();
		verify(this.securityContextRepository, never()).save(any(), any());
		verifyNoMoreInteractions(this.authenticationManager, this.successHandler, this.failureHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationSuccessThenSuccess() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		given(this.successHandler.onAuthenticationSuccess(any(), any())).willReturn(Mono.empty());
		given(this.securityContextRepository.save(any(), any())).willAnswer((a) -> Mono.just(a.getArguments()[0]));
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		client.get().uri("/").exchange().expectStatus().isOk().expectBody().isEmpty();
		verify(this.successHandler).onAuthenticationSuccess(any(), eq(authentication.block()));
		verify(this.securityContextRepository).save(any(), any());
		verifyNoMoreInteractions(this.failureHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationEmptyThenServerError() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.empty());
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		client.get().uri("/").exchange().expectStatus().is5xxServerError().expectBody().isEmpty();
		verify(this.securityContextRepository, never()).save(any(), any());
		verifyNoMoreInteractions(this.successHandler, this.failureHandler);
	}

	@Test
	public void filterWhenNotMatchAndConvertAndAuthenticationSuccessThenContinues() {
		this.filter.setRequiresAuthenticationMatcher((e) -> ServerWebExchangeMatcher.MatchResult.notMatch());
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();
		assertThat(result.getResponseCookies()).isEmpty();
		verifyNoMoreInteractions(this.authenticationConverter, this.authenticationManager, this.successHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationFailThenEntryPoint() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any()))
			.willReturn(Mono.error(new BadCredentialsException("Failed")));
		given(this.failureHandler.onAuthenticationFailure(any(), any())).willReturn(Mono.empty());
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		client.get().uri("/").exchange().expectStatus().isOk().expectBody().isEmpty();
		verify(this.failureHandler).onAuthenticationFailure(any(), any());
		verify(this.securityContextRepository, never()).save(any(), any());
		verifyNoMoreInteractions(this.successHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationExceptionThenServerError() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.error(new RuntimeException("Failed")));
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		client.get().uri("/").exchange().expectStatus().is5xxServerError().expectBody().isEmpty();
		verify(this.securityContextRepository, never()).save(any(), any());
		verifyNoMoreInteractions(this.successHandler, this.failureHandler);
	}

	@Test
	public void setRequiresAuthenticationMatcherWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequiresAuthenticationMatcher(null));
	}

	/**
	 * @author Rob Winch
	 * @since 7.0
	 */
	private static final class RunAsWebFilter implements WebFilter {

		private final Authentication authentication;

		private RunAsWebFilter(Authentication authentication) {
			this.authentication = authentication;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		}

	}

}
