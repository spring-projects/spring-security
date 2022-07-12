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

package org.springframework.security.authorization;

import java.util.Collections;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthenticatedAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class AuthenticatedAuthorizationManagerTests {

	@Test
	public void authenticatedWhenUserNotAnonymousAndAuthenticatedThenGrantedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN",
				"ROLE_USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void authenticatedWhenUserNullThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();
		Supplier<Authentication> authentication = () -> null;
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void authenticatedWhenUserAnonymousThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();
		Supplier<Authentication> authentication = () -> new AnonymousAuthenticationToken("key", "principal",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void authenticatedWhenUserNotAuthenticatedThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_ADMIN",
				"ROLE_USER");
		authentication.setAuthenticated(false);
		Object object = new Object();

		assertThat(manager.check(() -> authentication, object).isGranted()).isFalse();
	}

	@Test
	public void authenticatedWhenUserRememberMeThenGrantedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();
		Supplier<Authentication> authentication = () -> new RememberMeAuthenticationToken("user", "password",
				Collections.emptyList());
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void fullyAuthenticatedWhenUserNotAnonymousAndNotRememberMeThenGrantedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.fullyAuthenticated();
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN",
				"ROLE_USER");
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void fullyAuthenticatedWhenUserNullThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.fullyAuthenticated();
		Supplier<Authentication> authentication = () -> null;
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void fullyAuthenticatedWhenUserRememberMeThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.fullyAuthenticated();
		Supplier<Authentication> authentication = () -> new RememberMeAuthenticationToken("user", "password",
				Collections.emptyList());
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void fullyAuthenticatedWhenUserAnonymousThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.fullyAuthenticated();
		Supplier<Authentication> authentication = () -> new AnonymousAuthenticationToken("key", "principal",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void anonymousWhenUserAnonymousThenGrantedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.anonymous();
		Supplier<Authentication> authentication = () -> new AnonymousAuthenticationToken("key", "principal",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void anonymousWhenUserNotAnonymousThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.anonymous();
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN",
				"ROLE_USER");
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void rememberMeWhenUserRememberMeThenGrantedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.rememberMe();
		Supplier<Authentication> authentication = () -> new RememberMeAuthenticationToken("user", "password",
				Collections.emptyList());
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void rememberMeWhenUserNotRememberMeThenDeniedDecision() {
		AuthenticatedAuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.rememberMe();
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN",
				"ROLE_USER");
		Object object = new Object();
		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

}
