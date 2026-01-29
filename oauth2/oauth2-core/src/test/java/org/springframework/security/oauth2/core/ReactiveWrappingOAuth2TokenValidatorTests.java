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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.*;

/**
 * Tests for verifying {@link ReactiveWrappingOAuth2TokenValidatorTests}
 *
 * @author Iain Henderson
 */
public class ReactiveWrappingOAuth2TokenValidatorTests {

	private static final OAuth2Error DETAIL = new OAuth2Error("error", "description", "uri");

	@Test
	public void validate() {
		ReactiveWrappingOAuth2TokenValidator<OAuth2Token> tokenValidator =
				new ReactiveWrappingOAuth2TokenValidator<>(token -> OAuth2TokenValidatorResult.success());
		OAuth2Token token = mock(OAuth2Token.class);
		assertThat(tokenValidator.validate(token).block().hasErrors()).isFalse();
	}

	@Test
	public void validateFailure() {
		ReactiveWrappingOAuth2TokenValidator<OAuth2Token> tokenValidator =
				new ReactiveWrappingOAuth2TokenValidator<>(token -> OAuth2TokenValidatorResult.failure(DETAIL));
		OAuth2Token token = mock(OAuth2Token.class);
		OAuth2TokenValidatorResult result = tokenValidator.validate(token).block();
		assertThat(result).isNotNull();
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).containsExactly(DETAIL);
	}

	@Test
	public void constructorWhenInvokedWithNullValidatorListThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ReactiveWrappingOAuth2TokenValidator<>(null));
	}
}
