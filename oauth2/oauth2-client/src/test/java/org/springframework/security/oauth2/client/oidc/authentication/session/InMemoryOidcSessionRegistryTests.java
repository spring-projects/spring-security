/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.session;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import static org.assertj.core.api.Assertions.assertThat;

public class InMemoryOidcSessionRegistryTests {

	@Test
	public void registerWhenDefaultsThenStoresSessionInformation() {
		InMemoryOidcSessionRegistry registry = new InMemoryOidcSessionRegistry();
		String sessionId = "client";
		OidcSessionRegistration info = TestOidcSessionRegistrations.create(sessionId);
		registry.register(info);
		OidcLogoutToken token = TestOidcLogoutTokens.withUser(info.getPrincipal()).build();
		Iterable<OidcSessionRegistration> infos = registry.deregister(token);
		assertThat(infos).containsExactly(info);
	}

	@Test
	public void registerWhenIdTokenHasSessionIdThenStoresSessionInformation() {
		InMemoryOidcSessionRegistry registry = new InMemoryOidcSessionRegistry();
		OidcIdToken token = TestOidcIdTokens.idToken().claim("sid", "provider").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		OidcSessionRegistration info = TestOidcSessionRegistrations.create("client", user);
		registry.register(info);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSessionId(token.getIssuer().toString(), "provider")
				.build();
		Iterable<OidcSessionRegistration> infos = registry.deregister(logoutToken);
		assertThat(infos).containsExactly(info);
	}

	@Test
	public void unregisterWhenMultipleSessionsThenRemovesAllMatching() {
		InMemoryOidcSessionRegistry registry = new InMemoryOidcSessionRegistry();
		OidcIdToken token = TestOidcIdTokens.idToken().claim("sid", "providerOne").subject("otheruser").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		OidcSessionRegistration one = TestOidcSessionRegistrations.create("clientOne", user);
		registry.register(one);
		token = TestOidcIdTokens.idToken().claim("sid", "providerTwo").build();
		user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		OidcSessionRegistration two = TestOidcSessionRegistrations.create("clientTwo", user);
		registry.register(two);
		token = TestOidcIdTokens.idToken().claim("sid", "providerThree").build();
		user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		OidcSessionRegistration three = TestOidcSessionRegistrations.create("clientThree", user);
		registry.register(three);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSubject(token.getIssuer().toString(), token.getSubject())
				.build();
		Iterable<OidcSessionRegistration> infos = registry.deregister(logoutToken);
		assertThat(infos).containsExactlyInAnyOrder(two, three);
		logoutToken = TestOidcLogoutTokens.withSubject(token.getIssuer().toString(), "otheruser").build();
		infos = registry.deregister(logoutToken);
		assertThat(infos).containsExactly(one);
	}

	@Test
	public void unregisterWhenNoSessionsThenEmptyList() {
		InMemoryOidcSessionRegistry registry = new InMemoryOidcSessionRegistry();
		OidcIdToken token = TestOidcIdTokens.idToken().claim("sid", "provider").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		OidcSessionRegistration registration = TestOidcSessionRegistrations.create("client", user);
		registry.register(registration);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSessionId(token.getIssuer().toString(), "wrong").build();
		Iterable<?> infos = registry.deregister(logoutToken);
		assertThat(infos).isNotNull();
		assertThat(infos).isEmpty();
		logoutToken = TestOidcLogoutTokens.withSessionId("https://wrong", "provider").build();
		infos = registry.deregister(logoutToken);
		assertThat(infos).isNotNull();
		assertThat(infos).isEmpty();
	}

}
