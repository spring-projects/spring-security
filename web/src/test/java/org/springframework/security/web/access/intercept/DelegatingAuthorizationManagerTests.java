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

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link DelegatingAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @author Parikshit Dutta
 */
public class DelegatingAuthorizationManagerTests {

	@Test
	public void buildWhenMappingsEmptyThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> DelegatingAuthorizationManager.builder().build())
				.withMessage("mappings cannot be empty");
	}

	@Test
	public void addWhenMatcherNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> DelegatingAuthorizationManager.builder()
						.add(null, (a, o) -> new AuthorizationDecision(true)).build())
				.withMessage("matcher cannot be null");
	}

	@Test
	public void addWhenManagerNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> DelegatingAuthorizationManager.builder().add(new MvcRequestMatcher(null, "/grant"), null).build())
				.withMessage("manager cannot be null");
	}

	@Test
	public void checkWhenMultipleMappingsConfiguredThenDelegatesMatchingManager() {
		DelegatingAuthorizationManager manager = DelegatingAuthorizationManager.builder()
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
	public void testAuthorizationEventPublisherIsNotNull() {
		DelegatingAuthorizationManager manager = DelegatingAuthorizationManager.builder()
				.add(new MvcRequestMatcher(null, "/grant"), (a, o) -> new AuthorizationDecision(true)).build();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setAuthorizationEventPublisher(null))
				.withMessage("AuthorizationEventPublisher cannot be null");
	}

	@Test
	public void testAuthorizationSuccessEventWhenAuthorizationGranted() {
		DelegatingAuthorizationManager manager = DelegatingAuthorizationManager.builder()
				.add(new MvcRequestMatcher(null, "/grant"), (a, o) -> new AuthorizationDecision(true)).build();

		AuthorizationEventPublisher authorizationEventPublisher = mock(AuthorizationEventPublisher.class);
		manager.setAuthorizationEventPublisher(authorizationEventPublisher);

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");

		AuthorizationDecision grant = manager.check(authentication, new MockHttpServletRequest(null, "/grant"));
		verify(authorizationEventPublisher).publishAuthorizationSuccess(grant);
	}

	@Test
	public void testAuthorizationFailureEventWhenAuthorizationNotGranted() {
		DelegatingAuthorizationManager manager = DelegatingAuthorizationManager.builder()
				.add(new MvcRequestMatcher(null, "/deny"), (a, o) -> new AuthorizationDecision(false)).build();

		AuthorizationEventPublisher authorizationEventPublisher = mock(AuthorizationEventPublisher.class);
		manager.setAuthorizationEventPublisher(authorizationEventPublisher);

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");

		AuthorizationDecision grant = manager.check(authentication, new MockHttpServletRequest(null, "/deny"));
		verify(authorizationEventPublisher).publishAuthorizationFailure(grant);
	}

}
