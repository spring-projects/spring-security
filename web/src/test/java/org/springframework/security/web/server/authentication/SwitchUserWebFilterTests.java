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

package org.springframework.security.web.server.authentication;

import java.security.Principal;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Artur Otrzonsek
 */
@ExtendWith(MockitoExtension.class)
public class SwitchUserWebFilterTests {

	private SwitchUserWebFilter switchUserWebFilter;

	@Mock
	private ReactiveUserDetailsService userDetailsService;

	@Mock
	ServerAuthenticationSuccessHandler successHandler;

	@Mock
	private ServerAuthenticationFailureHandler failureHandler;

	@Mock
	private ServerSecurityContextRepository serverSecurityContextRepository;

	@BeforeEach
	public void setUp() {
		this.switchUserWebFilter = new SwitchUserWebFilter(this.userDetailsService, this.successHandler,
				this.failureHandler);
		this.switchUserWebFilter.setSecurityContextRepository(this.serverSecurityContextRepository);
	}

	@Test
	public void switchUserWhenRequestNotMatchThenDoesNothing() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/not/existing"));
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(exchange)).willReturn(Mono.empty());
		this.switchUserWebFilter.filter(exchange, chain).block();
		verifyNoInteractions(this.userDetailsService);
		verifyNoInteractions(this.successHandler);
		verifyNoInteractions(this.failureHandler);
		verifyNoInteractions(this.serverSecurityContextRepository);
		verify(chain).filter(exchange);
	}

	@Test
	public void switchUser() {
		final String targetUsername = "TEST_USERNAME";
		final UserDetails switchUserDetails = switchUserDetails(targetUsername, true);
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));
		final WebFilterChain chain = mock(WebFilterChain.class);
		final Authentication originalAuthentication = UsernamePasswordAuthenticationToken.unauthenticated("principal",
				"credentials");
		final SecurityContextImpl securityContext = new SecurityContextImpl(originalAuthentication);
		given(this.userDetailsService.findByUsername(targetUsername)).willReturn(Mono.just(switchUserDetails));
		given(this.serverSecurityContextRepository.save(eq(exchange), any(SecurityContext.class)))
				.willReturn(Mono.empty());
		given(this.successHandler.onAuthenticationSuccess(any(WebFilterExchange.class), any(Authentication.class)))
				.willReturn(Mono.empty());
		this.switchUserWebFilter.filter(exchange, chain)
				.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext))).block();
		verifyNoInteractions(chain);
		verify(this.userDetailsService).findByUsername(targetUsername);
		final ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.serverSecurityContextRepository).save(eq(exchange), securityContextCaptor.capture());
		final SecurityContext savedSecurityContext = securityContextCaptor.getValue();
		final ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.successHandler).onAuthenticationSuccess(any(WebFilterExchange.class),
				authenticationCaptor.capture());
		final Authentication switchUserAuthentication = authenticationCaptor.getValue();
		assertThat(switchUserAuthentication).isSameAs(savedSecurityContext.getAuthentication());
		assertThat(switchUserAuthentication.getName()).isEqualTo(targetUsername);
		assertThat(switchUserAuthentication.getAuthorities()).anyMatch(SwitchUserGrantedAuthority.class::isInstance);
		assertThat(switchUserAuthentication.getAuthorities())
				.anyMatch((a) -> a.getAuthority().contains(SwitchUserWebFilter.ROLE_PREVIOUS_ADMINISTRATOR));
		assertThat(switchUserAuthentication.getAuthorities().stream()
				.filter((a) -> a instanceof SwitchUserGrantedAuthority)
				.map((a) -> ((SwitchUserGrantedAuthority) a).getSource()).map(Principal::getName))
						.contains(originalAuthentication.getName());
	}

	@Test
	public void switchUserWhenUserAlreadySwitchedThenExitSwitchAndSwitchAgain() {
		final Authentication originalAuthentication = UsernamePasswordAuthenticationToken
				.unauthenticated("origPrincipal", "origCredentials");
		final GrantedAuthority switchAuthority = new SwitchUserGrantedAuthority(
				SwitchUserWebFilter.ROLE_PREVIOUS_ADMINISTRATOR, originalAuthentication);
		final Authentication switchUserAuthentication = UsernamePasswordAuthenticationToken
				.authenticated("switchPrincipal", "switchCredentials", Collections.singleton(switchAuthority));
		final SecurityContextImpl securityContext = new SecurityContextImpl(switchUserAuthentication);
		final String targetUsername = "newSwitchPrincipal";
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));
		final WebFilterChain chain = mock(WebFilterChain.class);
		given(this.serverSecurityContextRepository.save(eq(exchange), any(SecurityContext.class)))
				.willReturn(Mono.empty());
		given(this.successHandler.onAuthenticationSuccess(any(WebFilterExchange.class), any(Authentication.class)))
				.willReturn(Mono.empty());
		given(this.userDetailsService.findByUsername(targetUsername))
				.willReturn(Mono.just(switchUserDetails(targetUsername, true)));
		this.switchUserWebFilter.filter(exchange, chain)
				.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext))).block();
		final ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.successHandler).onAuthenticationSuccess(any(WebFilterExchange.class),
				authenticationCaptor.capture());
		final Authentication secondSwitchUserAuthentication = authenticationCaptor.getValue();
		assertThat(secondSwitchUserAuthentication.getName()).isEqualTo(targetUsername);
		assertThat(secondSwitchUserAuthentication.getAuthorities().stream()
				.filter((a) -> a instanceof SwitchUserGrantedAuthority)
				.map((a) -> ((SwitchUserGrantedAuthority) a).getSource()).map(Principal::getName).findFirst()
				.orElse(null)).isEqualTo(originalAuthentication.getName());
	}

	@Test
	public void switchUserWhenUsernameIsMissingThenThrowException() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate"));
		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(mock(Authentication.class));
		assertThatIllegalArgumentException().isThrownBy(() -> {
			Context securityContextHolder = ReactiveSecurityContextHolder
					.withSecurityContext(Mono.just(securityContext));
			this.switchUserWebFilter.filter(exchange, chain).contextWrite(securityContextHolder).block();
		}).withMessage("The userName can not be null.");
		verifyNoInteractions(chain);
	}

	@Test
	public void switchUserWhenExceptionThenCallFailureHandler() {
		final String targetUsername = "TEST_USERNAME";
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));
		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(mock(Authentication.class));
		final UserDetails switchUserDetails = switchUserDetails(targetUsername, false);
		given(this.userDetailsService.findByUsername(any(String.class))).willReturn(Mono.just(switchUserDetails));
		given(this.failureHandler.onAuthenticationFailure(any(WebFilterExchange.class), any(DisabledException.class)))
				.willReturn(Mono.empty());
		this.switchUserWebFilter.filter(exchange, chain)
				.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext))).block();
		verify(this.failureHandler).onAuthenticationFailure(any(WebFilterExchange.class), any(DisabledException.class));
		verifyNoInteractions(chain);
	}

	@Test
	public void switchUserWhenFailureHandlerNotDefinedThenReturnError() {
		this.switchUserWebFilter = new SwitchUserWebFilter(this.userDetailsService, this.successHandler, null);
		final String targetUsername = "TEST_USERNAME";
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate?username={targetUser}", targetUsername));
		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(mock(Authentication.class));
		final UserDetails switchUserDetails = switchUserDetails(targetUsername, false);
		given(this.userDetailsService.findByUsername(any(String.class))).willReturn(Mono.just(switchUserDetails));
		assertThatExceptionOfType(DisabledException.class).isThrownBy(() -> {
			Context securityContextHolder = ReactiveSecurityContextHolder
					.withSecurityContext(Mono.just(securityContext));
			this.switchUserWebFilter.filter(exchange, chain).contextWrite(securityContextHolder).block();
		});
		verifyNoInteractions(chain);
	}

	@Test
	public void exitSwitchThenReturnToOriginalAuthentication() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));
		final Authentication originalAuthentication = UsernamePasswordAuthenticationToken
				.unauthenticated("origPrincipal", "origCredentials");
		final GrantedAuthority switchAuthority = new SwitchUserGrantedAuthority(
				SwitchUserWebFilter.ROLE_PREVIOUS_ADMINISTRATOR, originalAuthentication);
		final Authentication switchUserAuthentication = UsernamePasswordAuthenticationToken
				.authenticated("switchPrincipal", "switchCredentials", Collections.singleton(switchAuthority));
		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(switchUserAuthentication);
		given(this.serverSecurityContextRepository.save(eq(exchange), any(SecurityContext.class)))
				.willReturn(Mono.empty());
		given(this.successHandler.onAuthenticationSuccess(any(WebFilterExchange.class), any(Authentication.class)))
				.willReturn(Mono.empty());
		this.switchUserWebFilter.filter(exchange, chain)
				.contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext))).block();
		final ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.serverSecurityContextRepository).save(eq(exchange), securityContextCaptor.capture());
		final SecurityContext savedSecurityContext = securityContextCaptor.getValue();
		final ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.successHandler).onAuthenticationSuccess(any(WebFilterExchange.class),
				authenticationCaptor.capture());
		final Authentication originalAuthenticationValue = authenticationCaptor.getValue();
		assertThat(savedSecurityContext.getAuthentication()).isSameAs(originalAuthentication);
		assertThat(originalAuthenticationValue).isSameAs(originalAuthentication);
		verifyNoInteractions(chain);
	}

	@Test
	public void exitSwitchWhenUserNotSwitchedThenThrowError() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));
		final Authentication originalAuthentication = UsernamePasswordAuthenticationToken
				.unauthenticated("origPrincipal", "origCredentials");
		final WebFilterChain chain = mock(WebFilterChain.class);
		final SecurityContextImpl securityContext = new SecurityContextImpl(originalAuthentication);
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class).isThrownBy(() -> {
			Context securityContextHolder = ReactiveSecurityContextHolder
					.withSecurityContext(Mono.just(securityContext));
			this.switchUserWebFilter.filter(exchange, chain).contextWrite(securityContextHolder).block();
		}).withMessage("Could not find original Authentication object");
		verifyNoInteractions(chain);
	}

	@Test
	public void exitSwitchWhenNoCurrentUserThenThrowError() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));
		final WebFilterChain chain = mock(WebFilterChain.class);
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(() -> this.switchUserWebFilter.filter(exchange, chain).block())
				.withMessage("No current user associated with this request");
		verifyNoInteractions(chain);
	}

	@Test
	public void constructorUserDetailsServiceRequired() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.switchUserWebFilter = new SwitchUserWebFilter(null,
						mock(ServerAuthenticationSuccessHandler.class), mock(ServerAuthenticationFailureHandler.class)))
				.withMessage("userDetailsService must be specified");
	}

	@Test
	public void constructorServerAuthenticationSuccessHandlerRequired() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class),
								null, mock(ServerAuthenticationFailureHandler.class)))
				.withMessage("successHandler must be specified");
	}

	@Test
	public void constructorSuccessTargetUrlRequired() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class), null,
						"failure/target/url"))
				.withMessage("successTargetUrl must be specified");
	}

	@Test
	public void constructorFirstDefaultValues() {
		this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class),
				mock(ServerAuthenticationSuccessHandler.class), mock(ServerAuthenticationFailureHandler.class));
		final Object securityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertThat(securityContextRepository).isInstanceOf(WebSessionServerSecurityContextRepository.class);
		final Object userDetailsChecker = ReflectionTestUtils.getField(this.switchUserWebFilter, "userDetailsChecker");
		assertThat(userDetailsChecker).isInstanceOf(AccountStatusUserDetailsChecker.class);
	}

	@Test
	public void constructorSecondDefaultValues() {
		this.switchUserWebFilter = new SwitchUserWebFilter(mock(ReactiveUserDetailsService.class), "success/target/url",
				"failure/target/url");
		final Object successHandler = ReflectionTestUtils.getField(this.switchUserWebFilter, "successHandler");
		assertThat(successHandler).isInstanceOf(RedirectServerAuthenticationSuccessHandler.class);
		final Object failureHandler = ReflectionTestUtils.getField(this.switchUserWebFilter, "failureHandler");
		assertThat(failureHandler).isInstanceOf(RedirectServerAuthenticationFailureHandler.class);
		final Object securityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertThat(securityContextRepository).isInstanceOf(WebSessionServerSecurityContextRepository.class);
		final Object userDetailsChecker = ReflectionTestUtils.getField(this.switchUserWebFilter, "userDetailsChecker");
		assertThat(userDetailsChecker instanceof AccountStatusUserDetailsChecker).isTrue();
	}

	@Test
	public void setSecurityContextRepositoryWhenNullThenThrowException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.switchUserWebFilter.setSecurityContextRepository(null))
				.withMessage("securityContextRepository cannot be null");
	}

	@Test
	public void setSecurityContextRepositoryWhenDefinedThenChangeDefaultValue() {
		final Object oldSecurityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertThat(oldSecurityContextRepository).isSameAs(this.serverSecurityContextRepository);
		final ServerSecurityContextRepository newSecurityContextRepository = mock(
				ServerSecurityContextRepository.class);
		this.switchUserWebFilter.setSecurityContextRepository(newSecurityContextRepository);
		final Object currentSecurityContextRepository = ReflectionTestUtils.getField(this.switchUserWebFilter,
				"securityContextRepository");
		assertThat(currentSecurityContextRepository).isSameAs(newSecurityContextRepository);
	}

	@Test
	public void setExitUserUrlWhenNullThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.switchUserWebFilter.setExitUserUrl(null))
				.withMessage("exitUserUrl cannot be empty and must be a valid redirect URL");
	}

	@Test
	public void setExitUserUrlWhenInvalidUrlThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.switchUserWebFilter.setExitUserUrl("wrongUrl"))
				.withMessage("exitUserUrl cannot be empty and must be a valid redirect URL");
	}

	@Test
	public void setExitUserUrlWhenDefinedThenChangeDefaultValue() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));
		final ServerWebExchangeMatcher oldExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");
		assertThat(oldExitUserMatcher.matches(exchange).block().isMatch()).isTrue();
		this.switchUserWebFilter.setExitUserUrl("/exit-url");
		final MockServerWebExchange newExchange = MockServerWebExchange.from(MockServerHttpRequest.post("/exit-url"));
		final ServerWebExchangeMatcher newExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");
		assertThat(newExitUserMatcher.matches(newExchange).block().isMatch()).isTrue();
	}

	@Test
	public void setExitUserMatcherWhenNullThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.switchUserWebFilter.setExitUserMatcher(null))
				.withMessage("exitUserMatcher cannot be null");
	}

	@Test
	public void setExitUserMatcherWhenDefinedThenChangeDefaultValue() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/logout/impersonate"));
		final ServerWebExchangeMatcher oldExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");
		assertThat(oldExitUserMatcher.matches(exchange).block().isMatch()).isTrue();
		final ServerWebExchangeMatcher newExitUserMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,
				"/exit-url");
		this.switchUserWebFilter.setExitUserMatcher(newExitUserMatcher);
		final ServerWebExchangeMatcher currentExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "exitUserMatcher");
		assertThat(currentExitUserMatcher).isSameAs(newExitUserMatcher);
	}

	@Test
	public void setSwitchUserUrlWhenNullThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.switchUserWebFilter.setSwitchUserUrl(null))
				.withMessage("switchUserUrl cannot be empty and must be a valid redirect URL");
	}

	@Test
	public void setSwitchUserUrlWhenInvalidThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.switchUserWebFilter.setSwitchUserUrl("wrongUrl"))
				.withMessage("switchUserUrl cannot be empty and must be a valid redirect URL");
	}

	@Test
	public void setSwitchUserUrlWhenDefinedThenChangeDefaultValue() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate"));
		final ServerWebExchangeMatcher oldSwitchUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");
		assertThat(oldSwitchUserMatcher.matches(exchange).block().isMatch()).isTrue();
		this.switchUserWebFilter.setSwitchUserUrl("/switch-url");
		final MockServerWebExchange newExchange = MockServerWebExchange.from(MockServerHttpRequest.post("/switch-url"));
		final ServerWebExchangeMatcher newSwitchUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");
		assertThat(newSwitchUserMatcher.matches(newExchange).block().isMatch()).isTrue();
	}

	@Test
	public void setSwitchUserMatcherWhenNullThenThrowException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.switchUserWebFilter.setSwitchUserMatcher(null))
				.withMessage("switchUserMatcher cannot be null");
	}

	@Test
	public void setSwitchUserMatcherWhenDefinedThenChangeDefaultValue() {
		final MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.post("/login/impersonate"));
		final ServerWebExchangeMatcher oldSwitchUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");
		assertThat(oldSwitchUserMatcher.matches(exchange).block().isMatch()).isTrue();
		final ServerWebExchangeMatcher newSwitchUserMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,
				"/switch-url");
		this.switchUserWebFilter.setSwitchUserMatcher(newSwitchUserMatcher);
		final ServerWebExchangeMatcher currentExitUserMatcher = (ServerWebExchangeMatcher) ReflectionTestUtils
				.getField(this.switchUserWebFilter, "switchUserMatcher");
		assertThat(currentExitUserMatcher).isSameAs(newSwitchUserMatcher);
	}

	private UserDetails switchUserDetails(String username, boolean enabled) {
		final SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_SWITCH_TEST");
		return new User(username, "NA", enabled, true, true, true, Collections.singleton(authority));
	}

}
