/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveOAuth2AuthorizationFailureHandler} that removes an
 * {@link OAuth2AuthorizedClient} when the {@link OAuth2Error#getErrorCode()} matches one
 * of the configured {@link OAuth2ErrorCodes OAuth 2.0 error codes}.
 *
 * @author Phil Clay
 * @since 5.3
 */
public class RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler
		implements ReactiveOAuth2AuthorizationFailureHandler {

	/**
	 * The default OAuth 2.0 error codes that will trigger removal of the authorized
	 * client.
	 * @see OAuth2ErrorCodes
	 */
	public static final Set<String> DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES;
	static {
		Set<String> codes = new LinkedHashSet<>();
		// Returned from resource servers when an access token provided is expired,
		// revoked, malformed, or invalid for other reasons. Note that this is needed
		// because the ServerOAuth2AuthorizedClientExchangeFilterFunction delegates this
		// type of failure received from a resource server to this failure handler.
		codes.add(OAuth2ErrorCodes.INVALID_TOKEN);
		// Returned from authorization servers when a refresh token is invalid, expired,
		// revoked, does not match the redirection URI used in the authorization request,
		// or was issued to another client.
		codes.add(OAuth2ErrorCodes.INVALID_GRANT);
		DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES = Collections.unmodifiableSet(codes);
	}

	/**
	 * A delegate that removes an {@link OAuth2AuthorizedClient} from a
	 * {@link ServerOAuth2AuthorizedClientRepository} or
	 * {@link ReactiveOAuth2AuthorizedClientService} if the error code is one of the
	 * {@link #removeAuthorizedClientErrorCodes}.
	 */
	private final OAuth2AuthorizedClientRemover delegate;

	/**
	 * The OAuth 2.0 Error Codes which will trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	private final Set<String> removeAuthorizedClientErrorCodes;

	/**
	 * Constructs a
	 * {@code RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler} using the
	 * provided parameters.
	 * @param authorizedClientRemover the {@link OAuth2AuthorizedClientRemover} used for
	 * removing an {@link OAuth2AuthorizedClient} if the error code is one of the
	 * {@link #DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES}.
	 */
	public RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
			OAuth2AuthorizedClientRemover authorizedClientRemover) {
		this(authorizedClientRemover, DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES);
	}

	/**
	 * Constructs a
	 * {@code RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler} using the
	 * provided parameters.
	 * @param authorizedClientRemover the {@link OAuth2AuthorizedClientRemover} used for
	 * removing an {@link OAuth2AuthorizedClient} if the error code is one of the
	 * {@link #removeAuthorizedClientErrorCodes}.
	 * @param removeAuthorizedClientErrorCodes the OAuth 2.0 error codes which will
	 * trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
			OAuth2AuthorizedClientRemover authorizedClientRemover, Set<String> removeAuthorizedClientErrorCodes) {
		Assert.notNull(authorizedClientRemover, "authorizedClientRemover cannot be null");
		Assert.notNull(removeAuthorizedClientErrorCodes, "removeAuthorizedClientErrorCodes cannot be null");
		this.removeAuthorizedClientErrorCodes = Collections
				.unmodifiableSet(new HashSet<>(removeAuthorizedClientErrorCodes));
		this.delegate = authorizedClientRemover;
	}

	@Override
	public Mono<Void> onAuthorizationFailure(OAuth2AuthorizationException authorizationException,
			Authentication principal, Map<String, Object> attributes) {
		if (authorizationException instanceof ClientAuthorizationException
				&& hasRemovalErrorCode(authorizationException)) {
			ClientAuthorizationException clientAuthorizationException = (ClientAuthorizationException) authorizationException;
			return this.delegate.removeAuthorizedClient(clientAuthorizationException.getClientRegistrationId(),
					principal, attributes);
		}
		return Mono.empty();
	}

	/**
	 * Returns true if the given exception has an error code that indicates that the
	 * authorized client should be removed.
	 * @param authorizationException the exception that caused the authorization failure
	 * @return true if the given exception has an error code that indicates that the
	 * authorized client should be removed.
	 */
	private boolean hasRemovalErrorCode(OAuth2AuthorizationException authorizationException) {
		return this.removeAuthorizedClientErrorCodes.contains(authorizationException.getError().getErrorCode());
	}

	/**
	 * Removes an {@link OAuth2AuthorizedClient} from a
	 * {@link ServerOAuth2AuthorizedClientRepository} or
	 * {@link ReactiveOAuth2AuthorizedClientService}.
	 */
	@FunctionalInterface
	public interface OAuth2AuthorizedClientRemover {

		/**
		 * Removes the {@link OAuth2AuthorizedClient} associated to the provided client
		 * registration identifier and End-User {@link Authentication} (Resource Owner).
		 * @param clientRegistrationId the identifier for the client's registration
		 * @param principal the End-User {@link Authentication} (Resource Owner)
		 * @param attributes an immutable {@code Map} of extra optional attributes present
		 * under certain conditions. For example, this might contain a
		 * {@link org.springframework.web.server.ServerWebExchange ServerWebExchange} if
		 * the authorization was performed within the context of a
		 * {@code ServerWebExchange}.
		 * @return an empty {@link Mono} that completes after this handler has finished
		 * handling the event.
		 */
		Mono<Void> removeAuthorizedClient(String clientRegistrationId, Authentication principal,
				Map<String, Object> attributes);

	}

}
