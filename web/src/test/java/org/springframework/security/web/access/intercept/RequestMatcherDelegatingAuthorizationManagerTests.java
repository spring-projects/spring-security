/*
 * Copyright 2002-2021 the original author or authors.
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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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
						.add(null, (a, o) -> new AuthorizationDecision(true)).build())
				.withMessage("matcher cannot be null");
	}

	@Test
	public void addWhenManagerNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder()
						.add(new MvcRequestMatcher(null, "/grant"), null).build())
				.withMessage("manager cannot be null");
	}

	@Test
	public void checkWhenMultipleMappingsConfiguredThenDelegatesMatchingManager() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
				.add(new MvcRequestMatcher(null, "/grant"), (a, o) -> new AuthorizationDecision(true))
				.add(new MvcRequestMatcher(null, "/deny"), (a, o) -> new AuthorizationDecision(false))
				.add(new MvcRequestMatcher(null, "/neutral"), (a, o) -> null).build();

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");

		AuthorizationDecision grant = manager.check(authentication, new MockHttpServletRequest(null, "/grant"));
		assertThat(grant).isNotNull();
		assertThat(grant.isGranted()).isTrue();

		AuthorizationDecision deny = manager.check(authentication, new MockHttpServletRequest(null, "/deny"));
		assertThat(deny).isNotNull();
		assertThat(deny.isGranted()).isFalse();

		AuthorizationDecision neutral = manager.check(authentication, new MockHttpServletRequest(null, "/neutral"));
		assertThat(neutral).isNull();

		AuthorizationDecision abstain = manager.check(authentication, new MockHttpServletRequest(null, "/abstain"));
		assertThat(abstain).isNull();
	}

	@Test
	public void checkWhenMultipleMappingsConfiguredWithConsumerThenDelegatesMatchingManager() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
				.mappings((m) -> {
					m.add(new RequestMatcherEntry<>(new MvcRequestMatcher(null, "/grant"),
							(a, o) -> new AuthorizationDecision(true)));
					m.add(new RequestMatcherEntry<>(AnyRequestMatcher.INSTANCE,
							AuthorityAuthorizationManager.hasRole("ADMIN")));
					m.add(new RequestMatcherEntry<>(new MvcRequestMatcher(null, "/afterAny"),
							(a, o) -> new AuthorizationDecision(true)));
				}).build();

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");

		AuthorizationDecision grant = manager.check(authentication, new MockHttpServletRequest(null, "/grant"));

		assertThat(grant).isNotNull();
		assertThat(grant.isGranted()).isTrue();

		AuthorizationDecision afterAny = manager.check(authentication, new MockHttpServletRequest(null, "/afterAny"));
		assertThat(afterAny).isNotNull();
		assertThat(afterAny.isGranted()).isFalse();

		AuthorizationDecision unmapped = manager.check(authentication, new MockHttpServletRequest(null, "/unmapped"));
		assertThat(unmapped).isNotNull();
		assertThat(unmapped.isGranted()).isFalse();
	}

	@Test
	public void checkWhenNoMatchesThenUsesDefaultAuthorizationManager() {
		RequestMatcherDelegatingAuthorizationManager manager = RequestMatcherDelegatingAuthorizationManager.builder()
				.add((request) -> false, (authentication, context) -> new AuthorizationDecision(false)).build();
		AuthorizationManager<RequestAuthorizationContext> defaultManager = mock(AuthorizationManager.class);
		given(defaultManager.check(any(), any())).willReturn(new AuthorizationDecision(true));
		manager.setDefaultAuthorizationManager(defaultManager);
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		AuthorizationDecision decision = manager.check(authentication, new MockHttpServletRequest(null, "/endpoint"));
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		verify(defaultManager).check(any(), any());
	}

	@Test
	public void addWhenMappingsConsumerNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> RequestMatcherDelegatingAuthorizationManager.builder().mappings(null).build())
				.withMessage("mappingsConsumer cannot be null");
	}

}
