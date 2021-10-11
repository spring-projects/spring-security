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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthorizationFailureHandler} that removes an
 * {@link OAuth2AuthorizedClient} when the {@link OAuth2Error#getErrorCode()} matches one
 * of the configured {@link OAuth2ErrorCodes OAuth 2.0 error codes}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientRepository
 * @see OAuth2AuthorizedClientService
 */
public class RemoveAuthorizedClientOAuth2AuthorizationFailureHandler implements OAuth2AuthorizationFailureHandler {

	/**
	 * The default OAuth 2.0 error codes that will trigger removal of an
	 * {@link OAuth2AuthorizedClient}.
	 * @see OAuth2ErrorCodes
	 */
	public static final Set<String> DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES;
	static {
		Set<String> codes = new LinkedHashSet<>();
		// Returned from Resource Servers when an access token provided is expired,
		// revoked, malformed, or invalid for other reasons. Note that this is needed
		// because ServletOAuth2AuthorizedClientExchangeFilterFunction delegates this type
		// of failure received from a Resource Server to this failure handler.
		codes.add(OAuth2ErrorCodes.INVALID_TOKEN);
		// Returned from Authorization Servers when the authorization grant or refresh
		// token is invalid, expired, revoked, does not match the redirection URI used in
		// the authorization request, or was issued to another client.
		codes.add(OAuth2ErrorCodes.INVALID_GRANT);
		DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES = Collections.unmodifiableSet(codes);
	}

	/**
	 * The OAuth 2.0 error codes which will trigger removal of an
	 * {@link OAuth2AuthorizedClient}.
	 * @see OAuth2ErrorCodes
	 */
	private final Set<String> removeAuthorizedClientErrorCodes;

	/**
	 * A delegate that removes an {@link OAuth2AuthorizedClient} from an
	 * {@link OAuth2AuthorizedClientRepository} or {@link OAuth2AuthorizedClientService}
	 * if the error code is one of the {@link #removeAuthorizedClientErrorCodes}.
	 */
	private final OAuth2AuthorizedClientRemover delegate;

	/**
	 * Constructs a {@code RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} using
	 * the provided parameters.
	 * @param authorizedClientRemover the {@link OAuth2AuthorizedClientRemover} used for
	 * removing an {@link OAuth2AuthorizedClient} if the error code is one of the
	 * {@link #DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES}.
	 */
	public RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
			OAuth2AuthorizedClientRemover authorizedClientRemover) {
		this(authorizedClientRemover, DEFAULT_REMOVE_AUTHORIZED_CLIENT_ERROR_CODES);
	}

	/**
	 * Constructs a {@code RemoveAuthorizedClientOAuth2AuthorizationFailureHandler} using
	 * the provided parameters.
	 * @param authorizedClientRemover the {@link OAuth2AuthorizedClientRemover} used for
	 * removing an {@link OAuth2AuthorizedClient} if the error code is one of the
	 * {@link #removeAuthorizedClientErrorCodes}.
	 * @param removeAuthorizedClientErrorCodes the OAuth 2.0 error codes which will
	 * trigger removal of an authorized client.
	 * @see OAuth2ErrorCodes
	 */
	public RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
			OAuth2AuthorizedClientRemover authorizedClientRemover, Set<String> removeAuthorizedClientErrorCodes) {
		Assert.notNull(authorizedClientRemover, "authorizedClientRemover cannot be null");
		Assert.notNull(removeAuthorizedClientErrorCodes, "removeAuthorizedClientErrorCodes cannot be null");
		this.removeAuthorizedClientErrorCodes = Collections
				.unmodifiableSet(new HashSet<>(removeAuthorizedClientErrorCodes));
		this.delegate = authorizedClientRemover;
	}

	@Override
	public void onAuthorizationFailure(OAuth2AuthorizationException authorizationException, Authentication principal,
			Map<String, Object> attributes) {
		if (authorizationException instanceof ClientAuthorizationException
				&& hasRemovalErrorCode(authorizationException)) {
			ClientAuthorizationException clientAuthorizationException = (ClientAuthorizationException) authorizationException;
			this.delegate.removeAuthorizedClient(clientAuthorizationException.getClientRegistrationId(), principal,
					attributes);
		}
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
	 * Removes an {@link OAuth2AuthorizedClient} from an
	 * {@link OAuth2AuthorizedClientRepository} or {@link OAuth2AuthorizedClientService}.
	 */
	@FunctionalInterface
	public interface OAuth2AuthorizedClientRemover {

		/**
		 * Removes the {@link OAuth2AuthorizedClient} associated to the provided client
		 * registration identifier and End-User {@link Authentication} (Resource Owner).
		 * @param clientRegistrationId the identifier for the client's registration
		 * @param principal the End-User {@link Authentication} (Resource Owner)
		 * @param attributes an immutable {@code Map} of (optional) attributes present
		 * under certain conditions. For example, this might contain a
		 * {@code jakarta.servlet.http.HttpServletRequest} and
		 * {@code jakarta.servlet.http.HttpServletResponse} if the authorization was
		 * performed within the context of a {@code jakarta.servlet.ServletContext}.
		 */
		void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
				Map<String, Object> attributes);

	}

}
