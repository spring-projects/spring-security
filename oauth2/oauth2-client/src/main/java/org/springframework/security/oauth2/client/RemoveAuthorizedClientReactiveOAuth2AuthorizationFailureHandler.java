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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An authorization failure handler that removes authorized clients from a
 * {@link ServerOAuth2AuthorizedClientRepository}
 * or a {@link ReactiveOAuth2AuthorizedClientService}.
 * for specific OAuth 2.0 error codes.
 *
 * @author Phil Clay
 * @since 5.3
 */
public class RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler implements ReactiveOAuth2AuthorizationFailureHandler {

	/**
	 * The default OAuth2 error codes that will trigger removal of the authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public static final Set<String>	DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
			/*
			 * Returned from resource servers when an access token provided is expired, revoked,
			 * malformed, or invalid for other reasons.
			 *
			 * Note that this is needed because the ServerOAuth2AuthorizedClientExchangeFilterFunction
			 * delegates this type of failure received from a resource server
			 * to this failure handler.
			 */
			OAuth2ErrorCodes.INVALID_TOKEN,
			/*
			 * Returned from authorization servers when a refresh token is invalid, expired, revoked,
			 * does not match the redirection URI used in the authorization request, or was issued to another client.
			 */
			OAuth2ErrorCodes.INVALID_GRANT)));

	/**
	 * A delegate that removes clients from either a
	 * {@link ServerOAuth2AuthorizedClientRepository}
	 * or a
	 * {@link ReactiveOAuth2AuthorizedClientService}
	 * if the error code is one of the {@link #removeAuthorizedClientErrorCodes}.
	 */
	private final OAuth2AuthorizedClientRemover delegate;

	/**
	 * The OAuth2 Error Codes which will trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	private final Set<String> removeAuthorizedClientErrorCodes;

	@FunctionalInterface
	private interface OAuth2AuthorizedClientRemover {
		Mono<Void> removeAuthorizedClient(
				String clientRegistrationId,
				Authentication principal,
				Map<String, Object> attributes);
	}

	/**
	 * @param authorizedClientRepository The repository from which authorized clients will be removed
	 * 		  if the error code is one of the {@link #DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES}.
	 */
	public RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		this(authorizedClientRepository, DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES);
	}

	/**
	 * @param authorizedClientRepository The repository from which authorized clients will be removed
	 * 		 if the error code is one of the {@code removeAuthorizedClientErrorCodes}.
	 * @param removeAuthorizedClientErrorCodes the OAuth2 Error Codes which will trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
			Set<String> removeAuthorizedClientErrorCodes) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		Assert.notNull(removeAuthorizedClientErrorCodes, "removeAuthorizedClientErrorCodes cannot be null");
		this.removeAuthorizedClientErrorCodes = Collections.unmodifiableSet(new HashSet<>(removeAuthorizedClientErrorCodes));
		this.delegate = (clientRegistrationId, principal, attributes) ->
				authorizedClientRepository.removeAuthorizedClient(
						clientRegistrationId,
						principal,
						(ServerWebExchange) attributes.get(ServerWebExchange.class.getName()));
	}

	/**
	 * @param authorizedClientService the service from which authorized clients will be removed
	 * 		  if the error code is one of the {@code removeAuthorizedClientErrorCodes}.
	 */
	public RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		this(authorizedClientService, DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES);
	}

	/**
	 * @param authorizedClientService the service from which authorized clients will be removed
	 * 		  if the error code is one of the {@code removeAuthorizedClientErrorCodes}.
	 * @param removeAuthorizedClientErrorCodes the OAuth2 Error Codes which will trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
			ReactiveOAuth2AuthorizedClientService authorizedClientService,
			Set<String> removeAuthorizedClientErrorCodes) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		Assert.notNull(removeAuthorizedClientErrorCodes, "removeAuthorizedClientErrorCodes cannot be null");
		this.removeAuthorizedClientErrorCodes = Collections.unmodifiableSet(new HashSet<>(removeAuthorizedClientErrorCodes));
		this.delegate = (clientRegistrationId, principal, attributes) ->
				authorizedClientService.removeAuthorizedClient(
						clientRegistrationId,
						principal.getName());
	}

	@Override
	public Mono<Void> onAuthorizationFailure(
			OAuth2AuthorizationException authorizationException,
			Authentication principal,
			Map<String, Object> attributes) {

		if (authorizationException instanceof ClientAuthorizationException
				&& hasRemovalErrorCode(authorizationException)) {

			ClientAuthorizationException clientAuthorizationException = (ClientAuthorizationException) authorizationException;
			return this.delegate.removeAuthorizedClient(
					clientAuthorizationException.getClientRegistrationId(),
					principal,
					attributes);
		} else {
			return Mono.empty();
		}
	}

	/**
	 * Returns true if the given exception has an error code that
	 * indicates that the authorized client should be removed.
	 *
	 * @param authorizationException the exception that caused the authorization failure
	 * @return true if the given exception has an error code that
	 * 		   indicates that the authorized client should be removed.
	 */
	private boolean hasRemovalErrorCode(OAuth2AuthorizationException authorizationException) {
		return this.removeAuthorizedClientErrorCodes.contains(authorizationException.getError().getErrorCode());
	}
}
