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

package org.springframework.security.web.access.intercept;

import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Tests for {@link RequestMatcherDelegatingAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @author Parikshit Dutta
 */
public class RequestMatcherDelegatingAuthorizationManagerTests {

	@Test
	public void buildWhenMappingsEmptyThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder().build())
			.withMessage("mappings cannot be empty");
	}

	@Test
	public void addWhenMatcherNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder()
				.add(null, SingleResultAuthorizationManager.permitAll())
				.build())
			.withMessage("matcher cannot be null");
	}

	@Test
	public void addWhenManagerNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> RequestMatcherDelegatingAuthorizationManager.builder().add(pathPattern("/grant"), null).build())
			.withMessage("manager cannot be null");
	}

	@Test
	public void checkWhenMultipleMappingsConfiguredThenDelegatesMatchingManager() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.add(pathPattern(null, "/grant"), SingleResultAuthorizationManager.permitAll())
			.add(pathPattern(null, "/deny"), SingleResultAuthorizationManager.denyAll())
			.build();

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");

		AuthorizationResult grant = manager.authorize(authentication, new MockHttpServletRequest(null, "/grant"));
		assertThat(grant).isNotNull();
		assertThat(grant.isGranted()).isTrue();

		AuthorizationResult deny = manager.authorize(authentication, new MockHttpServletRequest(null, "/deny"));
		assertThat(deny).isNotNull();
		assertThat(deny.isGranted()).isFalse();

		AuthorizationResult defaultDeny = manager.authorize(authentication,
				new MockHttpServletRequest(null, "/unmapped"));
		assertThat(defaultDeny).isNotNull();
		assertThat(defaultDeny.isGranted()).isFalse();
	}

	@Test
	public void checkWhenMultipleMappingsConfiguredWithConsumerThenDelegatesMatchingManager() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.mappings((m) -> {
				m.add(new RequestMatcherEntry<>(pathPattern("/grant"), SingleResultAuthorizationManager.permitAll()));
				m.add(new RequestMatcherEntry<>(AnyRequestMatcher.INSTANCE,
						AuthorityAuthorizationManager.hasRole("ADMIN")));
				m.add(new RequestMatcherEntry<>(pathPattern("/afterAny"),
						SingleResultAuthorizationManager.permitAll()));
			})
			.build();

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");

		AuthorizationResult grant = manager.authorize(authentication, new MockHttpServletRequest(null, "/grant"));

		assertThat(grant).isNotNull();
		assertThat(grant.isGranted()).isTrue();

		AuthorizationResult afterAny = manager.authorize(authentication, new MockHttpServletRequest(null, "/afterAny"));
		assertThat(afterAny).isNotNull();
		assertThat(afterAny.isGranted()).isFalse();

		AuthorizationResult unmapped = manager.authorize(authentication, new MockHttpServletRequest(null, "/unmapped"));
		assertThat(unmapped).isNotNull();
		assertThat(unmapped.isGranted()).isFalse();
	}

	@Test
	public void addWhenMappingsConsumerNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder().mappings(null).build())
			.withMessage("mappingsConsumer cannot be null");
	}

	@Test
	public void mappingsWhenConfiguredAfterAnyRequestThenException() {
		assertThatIllegalStateException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder()
				.anyRequest()
				.authenticated()
				.mappings((m) -> m.add(new RequestMatcherEntry<>(AnyRequestMatcher.INSTANCE,
						AuthenticatedAuthorizationManager.authenticated()))))
			.withMessage("Can't configure mappings after anyRequest");
	}

	@Test
	public void addWhenConfiguredAfterAnyRequestThenException() {
		assertThatIllegalStateException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder()
				.anyRequest()
				.authenticated()
				.add(AnyRequestMatcher.INSTANCE, AuthenticatedAuthorizationManager.authenticated()))
			.withMessage("Can't add mappings after anyRequest");
	}

	@Test
	public void requestMatchersWhenConfiguredAfterAnyRequestThenException() {
		assertThatIllegalStateException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder()
				.anyRequest()
				.authenticated()
				.requestMatchers(pathPattern("/authenticated"))
				.authenticated()
				.build())
			.withMessage("Can't configure requestMatchers after anyRequest");
	}

	@Test
	public void anyRequestWhenConfiguredAfterAnyRequestThenException() {
		assertThatIllegalStateException()
			.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder()
				.anyRequest()
				.authenticated()
				.anyRequest()
				.authenticated()
				.build())
			.withMessage("Can't configure anyRequest after itself");
	}

	@Test
	public void anyRequestWhenPermitAllThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.permitAll()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::anonymousUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void anyRequestWhenDenyAllThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.denyAll()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedAdmin, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authenticatedWhenAuthenticatedUserThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.authenticated()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authenticatedWhenAnonymousUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.authenticated()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::anonymousUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void fullyAuthenticatedWhenAuthenticatedUserThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.fullyAuthenticated()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void fullyAuthenticatedWhenAnonymousUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.fullyAuthenticated()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::anonymousUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void fullyAuthenticatedWhenRememberMeUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.fullyAuthenticated()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::rememberMeUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void rememberMeWhenRememberMeUserThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.rememberMe()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::rememberMeUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void rememberMeWhenAuthenticatedUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.rememberMe()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void anonymousWhenAnonymousUserThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.anonymous()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::anonymousUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void anonymousWhenAuthenticatedUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.anonymous()
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void hasRoleAdminWhenAuthenticatedUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasRole("ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void hasRoleAdminWhenAuthenticatedAdminThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasRole("ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedAdmin, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void hasAnyRoleUserOrAdminWhenAuthenticatedUserThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAnyRole("USER", "ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void hasAnyRoleUserOrAdminWhenAuthenticatedAdminThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAnyRole("USER", "ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedAdmin, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void hasAnyRoleUserOrAdminWhenAnonymousUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAnyRole("USER", "ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::anonymousUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void hasAuthorityRoleAdminWhenAuthenticatedUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAuthority("ROLE_ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void hasAuthorityRoleAdminWhenAuthenticatedAdminThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAuthority("ROLE_ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedAdmin, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void hasAnyAuthorityRoleUserOrAdminWhenAuthenticatedUserThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void hasAnyAuthorityRoleUserOrAdminWhenAuthenticatedAdminThenGrantedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedAdmin, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void hasAnyAuthorityRoleUserOrAdminWhenAnonymousUserThenDeniedDecision() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
			.anyRequest()
			.hasAnyRole("USER", "ADMIN")
			.build();
		AuthorizationResult decision = manager.authorize(TestAuthentication::anonymousUser, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

}
