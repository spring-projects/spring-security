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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An {@link OAuth2AuthorizationFailureHandler} that removes an {@link OAuth2AuthorizedClient}
 * from an {@link OAuth2AuthorizedClientRepository} or {@link OAuth2AuthorizedClientService}
 * for a specific set of OAuth 2.0 error codes.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClientService
 */
public class RemoveAuthorizedClientOAuth2AuthorizationFailureHandler implements OAuth2AuthorizationFailureHandler {

	/**
	 * The default OAuth 2.0 error codes that will trigger removal of an {@link OAuth2AuthorizedClient}.
	 * @see OAuth2ErrorCodes
	 */
	public static final Set<String>	DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
			/*
			 * Returned from Resource Servers when an access token provided is expired, revoked,
			 * malformed, or invalid for other reasons.
			 *
			 * Note that this is needed because ServletOAuth2AuthorizedClientExchangeFilterFunction
			 * delegates this type of failure received from a Resource Server
			 * to this failure handler.
			 */
			OAuth2ErrorCodes.INVALID_TOKEN,

			/*
			 * Returned from Authorization Servers when the authorization grant or refresh token is invalid, expired, revoked,
			 * does not match the redirection URI used in the authorization request, or was issued to another client.
			 */
			OAuth2ErrorCodes.INVALID_GRANT
	)));

	/**
	 * The OAuth 2.0 error codes which will trigger removal of an {@link OAuth2AuthorizedClient}.
	 * @see OAuth2ErrorCodes
	 */
	private final Set<String> removeAuthorizedClientErrorCodes;

	/**
	 * A delegate that removes an {@link OAuth2AuthorizedClient} from a
	 * {@link OAuth2AuthorizedClientRepository} or {@link OAuth2AuthorizedClientService}
	 * if the error code is one of the {@link #removeAuthorizedClientErrorCodes}.
	 */
	private final OAuth2AuthorizedClientRemover delegate;

	@FunctionalInterface
	private interface OAuth2AuthorizedClientRemover {
		void removeAuthorizedClient(String clientRegistrationId, Authentication principal, Map<String, Object> attributes);
	}

	/**
	 * Constructs a {@code RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} using the provided parameters.
	 *
	 * @param authorizedClientRepository the repository from which authorized clients will be removed
	 *                                   if the error code is one of the {@link #DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES}.
	 */
	public RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(OAuth2AuthorizedClientRepository authorizedClientRepository) {
		this(authorizedClientRepository, DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES);
	}

	/**
	 * Constructs a {@code RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} using the provided parameters.
	 *
	 * @param authorizedClientRepository the repository from which authorized clients will be removed
	 *                                   if the error code is one of the {@link #removeAuthorizedClientErrorCodes}.
	 * @param removeAuthorizedClientErrorCodes the OAuth 2.0 error codes which will trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			Set<String> removeAuthorizedClientErrorCodes) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		Assert.notNull(removeAuthorizedClientErrorCodes, "removeAuthorizedClientErrorCodes cannot be null");
		this.removeAuthorizedClientErrorCodes = Collections.unmodifiableSet(new HashSet<>(removeAuthorizedClientErrorCodes));
		this.delegate = (clientRegistrationId, principal, attributes) ->
				authorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal,
						(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
						(HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
	}

	/**
	 * Constructs a {@code RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} using the provided parameters.
	 *
	 * @param authorizedClientService the service from which authorized clients will be removed
	 *                                if the error code is one of the {@link #DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES}.
	 */
	public RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(OAuth2AuthorizedClientService authorizedClientService) {
		this(authorizedClientService, DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES);
	}

	/**
	 * Constructs a {@code RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} using the provided parameters.
	 *
	 * @param authorizedClientService the service from which authorized clients will be removed
	 *                                if the error code is one of the {@link #removeAuthorizedClientErrorCodes}.
	 * @param removeAuthorizedClientErrorCodes the OAuth 2.0 error codes which will trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
			OAuth2AuthorizedClientService authorizedClientService,
			Set<String> removeAuthorizedClientErrorCodes) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		Assert.notNull(removeAuthorizedClientErrorCodes, "removeAuthorizedClientErrorCodes cannot be null");
		this.removeAuthorizedClientErrorCodes = Collections.unmodifiableSet(new HashSet<>(removeAuthorizedClientErrorCodes));
		this.delegate = (clientRegistrationId, principal, attributes) ->
				authorizedClientService.removeAuthorizedClient(clientRegistrationId, principal.getName());
	}

	@Override
	public void onAuthorizationFailure(OAuth2AuthorizationException authorizationException,
			Authentication principal, Map<String, Object> attributes) {

		if (authorizationException instanceof ClientAuthorizationException &&
				hasRemovalErrorCode(authorizationException)) {
			ClientAuthorizationException clientAuthorizationException = (ClientAuthorizationException) authorizationException;
			this.delegate.removeAuthorizedClient(
					clientAuthorizationException.getClientRegistrationId(), principal, attributes);
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
