/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.springframework.util.Assert;

/**
 * A composite validator
 *
 * @param <T> the type of {@link AbstractOAuth2Token} this validator validates
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class DelegatingOAuth2TokenValidator<T extends AbstractOAuth2Token>
		implements OAuth2TokenValidator<T> {

	private final Collection<OAuth2TokenValidator<T>> tokenValidators;

	/**
	 * Constructs a {@code DelegatingOAuth2TokenValidator} using the provided validators.
	 *
	 * @param tokenValidators the {@link Collection} of {@link OAuth2TokenValidator}s to use
	 */
	public DelegatingOAuth2TokenValidator(Collection<OAuth2TokenValidator<T>> tokenValidators) {
		Assert.notNull(tokenValidators, "tokenValidators cannot be null");

		this.tokenValidators = new ArrayList<>(tokenValidators);
	}

	/**
	 * Constructs a {@code DelegatingOAuth2TokenValidator} using the provided validators.
	 *
	 * @param tokenValidators the collection of {@link OAuth2TokenValidator}s to use
	 */
	@SafeVarargs
	public DelegatingOAuth2TokenValidator(OAuth2TokenValidator<T>... tokenValidators) {
		this(Arrays.asList(tokenValidators));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OAuth2TokenValidatorResult validate(T token) {
		Collection<OAuth2Error> errors = new ArrayList<>();

		for ( OAuth2TokenValidator<T> validator : this.tokenValidators) {
			errors.addAll(validator.validate(token).getErrors());
		}

		return OAuth2TokenValidatorResult.failure(errors);
	}
}
