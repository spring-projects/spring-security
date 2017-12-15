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

import java.util.Objects;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.util.Assert;

/**
 * {@link OAuth2AuthenticationSessionDestroyedListener} is in charge of removing the
 * {@link org.springframework.security.oauth2.client.OAuth2AuthorizedClient} upon session
 * destroyed.
 * <p>
 * Note: This class use together with the
 * {@link org.springframework.security.web.session.HttpSessionEventPublisher}.
 * </p>
 * @author Kazuki Shimizu
 * @since 5.0
 */
public class OAuth2AuthenticationSessionDestroyedListener
		implements ApplicationListener<SessionDestroyedEvent> {

	private final OAuth2AuthorizedClientService authorizedClientService;

	/**
	 * Creates a new instance.
	 * @param authorizedClientService the {@link OAuth2AuthorizedClientService} to use
	 */
	public OAuth2AuthenticationSessionDestroyedListener(
			OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	/**
	 * Clears the
	 * {@link org.springframework.security.oauth2.client.OAuth2AuthorizedClient}.
	 *
	 * @param event indicates an event notifying that the session will be destroyed
	 * @see ApplicationListener#onApplicationEvent(ApplicationEvent)
	 */
	@Override
	public void onApplicationEvent(SessionDestroyedEvent event) {
		if (event.getSecurityContexts() == null) {
			return;
		}
		// @formatter:off
		event.getSecurityContexts().stream()
			.filter(Objects::nonNull)
			.map(SecurityContext::getAuthentication)
			.filter(OAuth2AuthenticationToken.class::isInstance)
			.map(OAuth2AuthenticationToken.class::cast)
			.forEach(this::removeAuthorizedClient);
		// @formatter:on
	}

	private void removeAuthorizedClient(OAuth2AuthenticationToken token) {
		this.authorizedClientService.removeAuthorizedClient(
				token.getAuthorizedClientRegistrationId(),
				token.getPrincipal().getName());
	}

}
