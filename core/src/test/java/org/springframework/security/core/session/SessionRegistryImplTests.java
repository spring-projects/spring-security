/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.session;

import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.core.context.SecurityContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link SessionRegistryImpl}.
 *
 * @author Ben Alex
 */
public class SessionRegistryImplTests {

	private SessionRegistryImpl sessionRegistry;

	@Before
	public void setUp() {
		this.sessionRegistry = new SessionRegistryImpl();
	}

	@Test
	public void sessionDestroyedEventRemovesSessionFromRegistry() {
		Object principal = "Some principal object";
		final String sessionId = "zzzz";
		// Register new Session
		this.sessionRegistry.registerNewSession(sessionId, principal);
		// De-register session via an ApplicationEvent
		this.sessionRegistry.onApplicationEvent(new SessionDestroyedEvent("") {
			@Override
			public String getId() {
				return sessionId;
			}

			@Override
			public List<SecurityContext> getSecurityContexts() {
				return null;
			}
		});
		// Check attempts to retrieve cleared session return null
		assertThat(this.sessionRegistry.getSessionInformation(sessionId)).isNull();
	}

	@Test
	public void sessionIdChangedEventRemovesOldSessionAndAddsANewSession() {
		Object principal = "Some principal object";
		final String sessionId = "zzzz";
		final String newSessionId = "123";
		// Register new Session
		this.sessionRegistry.registerNewSession(sessionId, principal);
		// De-register session via an ApplicationEvent
		this.sessionRegistry.onApplicationEvent(new SessionIdChangedEvent("") {
			@Override
			public String getOldSessionId() {
				return sessionId;
			}

			@Override
			public String getNewSessionId() {
				return newSessionId;
			}
		});
		assertThat(this.sessionRegistry.getSessionInformation(sessionId)).isNull();
		assertThat(this.sessionRegistry.getSessionInformation(newSessionId)).isNotNull();
		assertThat(this.sessionRegistry.getSessionInformation(newSessionId).getPrincipal()).isEqualTo(principal);
	}

	@Test
	public void testMultiplePrincipals() {
		Object principal1 = "principal_1";
		Object principal2 = "principal_2";
		String sessionId1 = "1234567890";
		String sessionId2 = "9876543210";
		String sessionId3 = "5432109876";
		this.sessionRegistry.registerNewSession(sessionId1, principal1);
		this.sessionRegistry.registerNewSession(sessionId2, principal1);
		this.sessionRegistry.registerNewSession(sessionId3, principal2);
		assertThat(this.sessionRegistry.getAllPrincipals()).hasSize(2);
		assertThat(this.sessionRegistry.getAllPrincipals().contains(principal1)).isTrue();
		assertThat(this.sessionRegistry.getAllPrincipals().contains(principal2)).isTrue();
	}

	@Test
	public void testSessionInformationLifecycle() throws Exception {
		Object principal = "Some principal object";
		String sessionId = "1234567890";
		// Register new Session
		this.sessionRegistry.registerNewSession(sessionId, principal);
		// Retrieve existing session by session ID
		Date currentDateTime = this.sessionRegistry.getSessionInformation(sessionId).getLastRequest();
		assertThat(this.sessionRegistry.getSessionInformation(sessionId).getPrincipal()).isEqualTo(principal);
		assertThat(this.sessionRegistry.getSessionInformation(sessionId).getSessionId()).isEqualTo(sessionId);
		assertThat(this.sessionRegistry.getSessionInformation(sessionId).getLastRequest()).isNotNull();
		// Retrieve existing session by principal
		assertThat(this.sessionRegistry.getAllSessions(principal, false)).hasSize(1);
		// Sleep to ensure SessionRegistryImpl will update time
		Thread.sleep(1000);
		// Update request date/time
		this.sessionRegistry.refreshLastRequest(sessionId);
		Date retrieved = this.sessionRegistry.getSessionInformation(sessionId).getLastRequest();
		assertThat(retrieved.after(currentDateTime)).isTrue();
		// Check it retrieves correctly when looked up via principal
		assertThat(this.sessionRegistry.getAllSessions(principal, false).get(0).getLastRequest()).isCloseTo(retrieved,
				2000L);
		// Clear session information
		this.sessionRegistry.removeSessionInformation(sessionId);
		// Check attempts to retrieve cleared session return null
		assertThat(this.sessionRegistry.getSessionInformation(sessionId)).isNull();
		assertThat(this.sessionRegistry.getAllSessions(principal, false)).isEmpty();
	}

	@Test
	public void testTwoSessionsOnePrincipalExpiring() {
		Object principal = "Some principal object";
		String sessionId1 = "1234567890";
		String sessionId2 = "9876543210";
		this.sessionRegistry.registerNewSession(sessionId1, principal);
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal, false);
		assertThat(sessions).hasSize(1);
		assertThat(contains(sessionId1, principal)).isTrue();
		this.sessionRegistry.registerNewSession(sessionId2, principal);
		sessions = this.sessionRegistry.getAllSessions(principal, false);
		assertThat(sessions).hasSize(2);
		assertThat(contains(sessionId2, principal)).isTrue();
		// Expire one session
		SessionInformation session = this.sessionRegistry.getSessionInformation(sessionId2);
		session.expireNow();
		// Check retrieval still correct
		assertThat(this.sessionRegistry.getSessionInformation(sessionId2).isExpired()).isTrue();
		assertThat(this.sessionRegistry.getSessionInformation(sessionId1).isExpired()).isFalse();
	}

	@Test
	public void testTwoSessionsOnePrincipalHandling() {
		Object principal = "Some principal object";
		String sessionId1 = "1234567890";
		String sessionId2 = "9876543210";
		this.sessionRegistry.registerNewSession(sessionId1, principal);
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal, false);
		assertThat(sessions).hasSize(1);
		assertThat(contains(sessionId1, principal)).isTrue();
		this.sessionRegistry.registerNewSession(sessionId2, principal);
		sessions = this.sessionRegistry.getAllSessions(principal, false);
		assertThat(sessions).hasSize(2);
		assertThat(contains(sessionId2, principal)).isTrue();
		this.sessionRegistry.removeSessionInformation(sessionId1);
		sessions = this.sessionRegistry.getAllSessions(principal, false);
		assertThat(sessions).hasSize(1);
		assertThat(contains(sessionId2, principal)).isTrue();
		this.sessionRegistry.removeSessionInformation(sessionId2);
		assertThat(this.sessionRegistry.getSessionInformation(sessionId2)).isNull();
		assertThat(this.sessionRegistry.getAllSessions(principal, false)).isEmpty();
	}

	private boolean contains(String sessionId, Object principal) {
		List<SessionInformation> info = this.sessionRegistry.getAllSessions(principal, false);
		for (SessionInformation sessionInformation : info) {
			if (sessionId.equals(sessionInformation.getSessionId())) {
				return true;
			}
		}
		return false;
	}

}
