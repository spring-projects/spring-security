/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client;

import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Tests for {@link OAuth2AuthorizedClientSessionDestroyedListener}.
 *
 * @author Kazuki Shimizu
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthorizedClientSessionDestroyedListenerTests {

	@Mock
	private OAuth2AuthorizedClientService authorizedClientService;

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullOAuth2AuthorizedClientService() {
		new OAuth2AuthorizedClientSessionDestroyedListener(null);
	}

	@Test
	public void removesAuthorizedClient() {

		String clientRegistrationId = "google";
		String principalName = "foo";
		OAuth2User user = mock(OAuth2User.class);
		when(user.getName()).thenReturn(principalName);

		SessionDestroyedEvent event = new SessionDestroyedEvent(this) {
			@Override
			public List<SecurityContext> getSecurityContexts() {
				List<SecurityContext> contexts = new ArrayList<>();
				// non OAuth2AuthenticationToken
				contexts.add(new SecurityContextImpl(
						new TestingAuthenticationToken("user", "password")));
				// authentication is null
				contexts.add(new SecurityContextImpl());
				// context is null
				contexts.add(null);
				contexts.add(new SecurityContextImpl(new OAuth2AuthenticationToken(user,
						Collections.emptyList(), clientRegistrationId)));
				return contexts;
			}

			@Override
			public String getId() {
				return toString();
			}
		};

		ApplicationListener<SessionDestroyedEvent> listener = new OAuth2AuthorizedClientSessionDestroyedListener(
				authorizedClientService);
		listener.onApplicationEvent(event);

		verify(authorizedClientService, times(1))
				.removeAuthorizedClient(clientRegistrationId, principalName);
		verify(authorizedClientService, times(1)).removeAuthorizedClient(anyString(),
				anyString());

	}

	@Test
	public void securityContextsIsNull() {

		SessionDestroyedEvent event = new SessionDestroyedEvent(this) {
			@Override
			public List<SecurityContext> getSecurityContexts() {
				return null;
			}

			@Override
			public String getId() {
				return toString();
			}
		};

		ApplicationListener<SessionDestroyedEvent> listener = new OAuth2AuthorizedClientSessionDestroyedListener(
				authorizedClientService);
		listener.onApplicationEvent(event);

		verifyZeroInteractions(authorizedClientService);

	}

	@Test
	public void securityContextsIsEmpty() {

		SessionDestroyedEvent event = new SessionDestroyedEvent(this) {
			@Override
			public List<SecurityContext> getSecurityContexts() {
				return Collections.emptyList();
			}

			@Override
			public String getId() {
				return toString();
			}
		};

		ApplicationListener<SessionDestroyedEvent> listener = new OAuth2AuthorizedClientSessionDestroyedListener(
				authorizedClientService);
		listener.onApplicationEvent(event);

		verifyZeroInteractions(authorizedClientService);

	}
}
