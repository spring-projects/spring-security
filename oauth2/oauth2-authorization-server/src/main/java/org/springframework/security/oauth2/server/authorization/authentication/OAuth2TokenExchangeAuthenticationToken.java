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

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Token Exchange Grant.
 *
 * @author Steve Riesenberg
 * @since 1.3
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2TokenExchangeAuthenticationProvider
 */
public class OAuth2TokenExchangeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final String requestedTokenType;

	private final String subjectToken;

	private final String subjectTokenType;

	private final String actorToken;

	private final String actorTokenType;

	private final Set<String> resources;

	private final Set<String> audiences;

	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2TokenExchangeAuthenticationToken} using the provided
	 * parameters.
	 * @param requestedTokenType the requested token type
	 * @param subjectToken the subject token
	 * @param subjectTokenType the subject token type
	 * @param clientPrincipal the authenticated client principal
	 * @param actorToken the actor token
	 * @param actorTokenType the actor token type
	 * @param resources the requested resource URI(s)
	 * @param audiences the requested audience value(s)
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2TokenExchangeAuthenticationToken(String requestedTokenType, String subjectToken,
			String subjectTokenType, Authentication clientPrincipal, @Nullable String actorToken,
			@Nullable String actorTokenType, @Nullable Set<String> resources, @Nullable Set<String> audiences,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType.TOKEN_EXCHANGE, clientPrincipal, additionalParameters);
		Assert.hasText(requestedTokenType, "requestedTokenType cannot be empty");
		Assert.hasText(subjectToken, "subjectToken cannot be empty");
		Assert.hasText(subjectTokenType, "subjectTokenType cannot be empty");
		this.requestedTokenType = requestedTokenType;
		this.subjectToken = subjectToken;
		this.subjectTokenType = subjectTokenType;
		this.actorToken = actorToken;
		this.actorTokenType = actorTokenType;
		this.resources = Collections
			.unmodifiableSet((resources != null) ? new LinkedHashSet<>(resources) : Collections.emptySet());
		this.audiences = Collections
			.unmodifiableSet((audiences != null) ? new LinkedHashSet<>(audiences) : Collections.emptySet());
		this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
	}

	/**
	 * Returns the requested token type.
	 * @return the requested token type
	 */
	public String getRequestedTokenType() {
		return this.requestedTokenType;
	}

	/**
	 * Returns the subject token.
	 * @return the subject token
	 */
	public String getSubjectToken() {
		return this.subjectToken;
	}

	/**
	 * Returns the subject token type.
	 * @return the subject token type
	 */
	public String getSubjectTokenType() {
		return this.subjectTokenType;
	}

	/**
	 * Returns the actor token.
	 * @return the actor token
	 */
	public String getActorToken() {
		return this.actorToken;
	}

	/**
	 * Returns the actor token type.
	 * @return the actor token type
	 */
	public String getActorTokenType() {
		return this.actorTokenType;
	}

	/**
	 * Returns the requested resource URI(s).
	 * @return the requested resource URI(s), or an empty {@code Set} if not available
	 */
	public Set<String> getResources() {
		return this.resources;
	}

	/**
	 * Returns the requested audience value(s).
	 * @return the requested audience value(s), or an empty {@code Set} if not available
	 */
	public Set<String> getAudiences() {
		return this.audiences;
	}

	/**
	 * Returns the requested scope(s).
	 * @return the requested scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

}
