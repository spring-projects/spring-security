/*
 * Copyright 2026-present the original author or authors.
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

import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * A reactive wrapper for synchronous validators
 *
 * @param <T> the type of {@link OAuth2Token} this validator validates
 * @author Iain Henderson
 */
public final class ReactiveWrappingOAuth2TokenValidator<T extends OAuth2Token> implements ReactiveOAuth2TokenValidator<T> {

	private final OAuth2TokenValidator<T> tokenValidator;

	/**
	 * Constructs a {@code ReactiveWrappingOAuth2TokenValidator} using the provided validator.
	 * @param tokenValidator the {@link OAuth2TokenValidator}s to use
	 */
	public ReactiveWrappingOAuth2TokenValidator(OAuth2TokenValidator<T> tokenValidator) {
		Assert.notNull(tokenValidator, "tokenValidator cannot be null");
		this.tokenValidator = tokenValidator;
	}

	@Override
	public Mono<OAuth2TokenValidatorResult> validate(T token) {
		return Mono.just(tokenValidator.validate(token))
				.map(OAuth2TokenValidatorResult::getErrors)
				.map(OAuth2TokenValidatorResult::failure);
	}
}
