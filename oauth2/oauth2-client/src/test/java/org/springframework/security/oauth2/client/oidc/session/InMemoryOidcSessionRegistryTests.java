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

package org.springframework.security.oauth2.client.oidc.session;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link InMemoryOidcSessionRegistry}
 */
public class InMemoryOidcSessionRegistryTests {

	@Test
	public void registerWhenDefaultsThenStoresSessionInformation() {
		InMemoryOidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();
		String sessionId = "client";
		OidcSessionInformation info = TestOidcSessionInformations.create(sessionId);
		sessionRegistry.saveSessionInformation(info);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withUser(info.getPrincipal()).build();
		Iterable<OidcSessionInformation> infos = sessionRegistry.removeSessionInformation(logoutToken);
		assertThat(infos).containsExactly(info);
	}

	@Test
	public void registerWhenIdTokenHasSessionIdThenStoresSessionInformation() {
		InMemoryOidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();
		OidcIdToken idToken = TestOidcIdTokens.idToken().claim("sid", "provider").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken);
		OidcSessionInformation info = TestOidcSessionInformations.create("client", user);
		sessionRegistry.saveSessionInformation(info);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSessionId(idToken.getIssuer().toString(), "provider")
			.build();
		Iterable<OidcSessionInformation> infos = sessionRegistry.removeSessionInformation(logoutToken);
		assertThat(infos).containsExactly(info);
	}

	@Test
	public void unregisterWhenMultipleSessionsThenRemovesAllMatching() {
		InMemoryOidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();
		OidcIdToken idToken = TestOidcIdTokens.idToken().claim("sid", "providerOne").subject("otheruser").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken);
		OidcSessionInformation oneSession = TestOidcSessionInformations.create("clientOne", user);
		sessionRegistry.saveSessionInformation(oneSession);
		idToken = TestOidcIdTokens.idToken().claim("sid", "providerTwo").build();
		user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken);
		OidcSessionInformation twoSession = TestOidcSessionInformations.create("clientTwo", user);
		sessionRegistry.saveSessionInformation(twoSession);
		idToken = TestOidcIdTokens.idToken().claim("sid", "providerThree").build();
		user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken);
		OidcSessionInformation threeSession = TestOidcSessionInformations.create("clientThree", user);
		sessionRegistry.saveSessionInformation(threeSession);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens
			.withSubject(idToken.getIssuer().toString(), idToken.getSubject())
			.build();
		Iterable<OidcSessionInformation> infos = sessionRegistry.removeSessionInformation(logoutToken);
		assertThat(infos).containsExactlyInAnyOrder(twoSession, threeSession);
		logoutToken = TestOidcLogoutTokens.withSubject(idToken.getIssuer().toString(), "otheruser").build();
		infos = sessionRegistry.removeSessionInformation(logoutToken);
		assertThat(infos).containsExactly(oneSession);
	}

	@Test
	public void unregisterWhenNoSessionsThenEmptyList() {
		InMemoryOidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();
		OidcIdToken idToken = TestOidcIdTokens.idToken().claim("sid", "provider").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken);
		OidcSessionInformation info = TestOidcSessionInformations.create("client", user);
		sessionRegistry.saveSessionInformation(info);
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSessionId(idToken.getIssuer().toString(), "wrong")
			.build();
		Iterable<?> infos = sessionRegistry.removeSessionInformation(logoutToken);
		assertThat(infos).isNotNull();
		assertThat(infos).isEmpty();
		logoutToken = TestOidcLogoutTokens.withSessionId("https://wrong", "provider").build();
		infos = sessionRegistry.removeSessionInformation(logoutToken);
		assertThat(infos).isNotNull();
		assertThat(infos).isEmpty();
	}

}
