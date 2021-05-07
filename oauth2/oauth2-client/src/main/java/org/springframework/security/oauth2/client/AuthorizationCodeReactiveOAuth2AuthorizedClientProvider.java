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

package org.springframework.security.oauth2.client;

import reactor.core.publisher.Mono;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * An implementation of a {@link ReactiveOAuth2AuthorizedClientProvider} for the
 * {@link AuthorizationGrantType#AUTHORIZATION_CODE authorization_code} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ReactiveOAuth2AuthorizedClientProvider
 */
public final class AuthorizationCodeReactiveOAuth2AuthorizedClientProvider
		implements ReactiveOAuth2AuthorizedClientProvider {

	/**
	 * Attempt to authorize the {@link OAuth2AuthorizationContext#getClientRegistration()
	 * client} in the provided {@code context}. Returns an empty {@code Mono} if
	 * authorization is not supported, e.g. the client's
	 * {@link ClientRegistration#getAuthorizationGrantType() authorization grant type} is
	 * not {@link AuthorizationGrantType#AUTHORIZATION_CODE authorization_code} OR the
	 * client is already authorized.
	 * @param context the context that holds authorization-specific state for the client
	 * @return an empty {@code Mono} if authorization is not supported or the client is
	 * already authorized
	 * @throws ClientAuthorizationRequiredException in order to trigger authorization in
	 * which the {@link OAuth2AuthorizationRequestRedirectWebFilter} will catch and
	 * initiate the authorization request
	 */
	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
				context.getClientRegistration().getAuthorizationGrantType()) && context.getAuthorizedClient() == null) {
			// ClientAuthorizationRequiredException is caught by
			// OAuth2AuthorizationRequestRedirectWebFilter which initiates authorization
			return Mono.error(() -> new ClientAuthorizationRequiredException(
					context.getClientRegistration().getRegistrationId()));
		}
		return Mono.empty();
	}

}
