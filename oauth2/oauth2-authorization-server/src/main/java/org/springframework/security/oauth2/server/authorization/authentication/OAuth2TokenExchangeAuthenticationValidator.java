/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.CollectionUtils;

/**
 * A {@code Consumer} providing access to the
 * {@link OAuth2TokenExchangeAuthenticationContext} containing an
 * {@link OAuth2TokenExchangeAuthenticationToken} and is the default
 * {@link OAuth2TokenExchangeAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OAuth 2.0 Token Exchange Grant
 * Request parameters.
 *
 * <p>
 * The default implementation validates
 * {@link OAuth2TokenExchangeAuthenticationToken#getScopes()}. If validation fails, an
 * {@link OAuth2AuthenticationException} is thrown.
 *
 * @author Rakesh Kumar Singh
 * @since 7.1
 * @see OAuth2TokenExchangeAuthenticationContext
 * @see OAuth2TokenExchangeAuthenticationToken
 * @see OAuth2TokenExchangeAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2TokenExchangeAuthenticationValidator
		implements Consumer<OAuth2TokenExchangeAuthenticationContext> {

	private static final Log LOGGER = LogFactory.getLog(OAuth2TokenExchangeAuthenticationValidator.class);

	/**
	 * The default validator for
	 * {@link OAuth2TokenExchangeAuthenticationToken#getScopes()}.
	 */
	public static final Consumer<OAuth2TokenExchangeAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OAuth2TokenExchangeAuthenticationValidator::validateScope;

	private final Consumer<OAuth2TokenExchangeAuthenticationContext> authenticationValidator = DEFAULT_SCOPE_VALIDATOR;

	@Override
	public void accept(OAuth2TokenExchangeAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateScope(OAuth2TokenExchangeAuthenticationContext authenticationContext) {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = authenticationContext.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
		OAuth2Authorization subjectAuthorization = authenticationContext.getSubjectAuthorization();

		Set<String> requestedScopes = tokenExchangeAuthentication.getScopes();
		if (CollectionUtils.isEmpty(requestedScopes)) {
			requestedScopes = subjectAuthorization.getAuthorizedScopes();
		}

		Set<String> allowedScopes = registeredClient.getScopes();
		if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format(
						"Invalid request: requested scope is not allowed" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}
	}

}
