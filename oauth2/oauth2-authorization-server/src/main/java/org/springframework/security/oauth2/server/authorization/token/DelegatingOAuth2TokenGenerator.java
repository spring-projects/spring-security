/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.token;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2TokenGenerator} that simply delegates to it's internal {@code List} of
 * {@link OAuth2TokenGenerator}(s).
 * <p>
 * Each {@link OAuth2TokenGenerator} is given a chance to
 * {@link OAuth2TokenGenerator#generate(OAuth2TokenContext)} with the first
 * {@code non-null} {@link OAuth2Token} being returned.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2TokenGenerator
 * @see JwtGenerator
 * @see OAuth2RefreshTokenGenerator
 */
public final class DelegatingOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

	private final List<OAuth2TokenGenerator<OAuth2Token>> tokenGenerators;

	/**
	 * Constructs a {@code DelegatingOAuth2TokenGenerator} using the provided parameters.
	 * @param tokenGenerators an array of {@link OAuth2TokenGenerator}(s)
	 */
	@SafeVarargs
	public DelegatingOAuth2TokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token>... tokenGenerators) {
		Assert.notEmpty(tokenGenerators, "tokenGenerators cannot be empty");
		Assert.noNullElements(tokenGenerators, "tokenGenerator cannot be null");
		this.tokenGenerators = Collections.unmodifiableList(asList(tokenGenerators));
	}

	@Nullable
	@Override
	public OAuth2Token generate(OAuth2TokenContext context) {
		for (OAuth2TokenGenerator<OAuth2Token> tokenGenerator : this.tokenGenerators) {
			OAuth2Token token = tokenGenerator.generate(context);
			if (token != null) {
				return token;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private static List<OAuth2TokenGenerator<OAuth2Token>> asList(
			OAuth2TokenGenerator<? extends OAuth2Token>... tokenGenerators) {

		List<OAuth2TokenGenerator<OAuth2Token>> tokenGeneratorList = new ArrayList<>();
		for (OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator : tokenGenerators) {
			tokenGeneratorList.add((OAuth2TokenGenerator<OAuth2Token>) tokenGenerator);
		}
		return tokenGeneratorList;
	}

}
