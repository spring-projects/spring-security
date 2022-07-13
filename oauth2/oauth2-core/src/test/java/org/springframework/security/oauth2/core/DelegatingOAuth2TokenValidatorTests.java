/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Arrays;
import java.util.Collection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for verifying {@link DelegatingOAuth2TokenValidator}
 *
 * @author Josh Cummings
 */
public class DelegatingOAuth2TokenValidatorTests {

	private static final OAuth2Error DETAIL = new OAuth2Error("error", "description", "uri");

	@Test
	public void validateWhenNoValidatorsConfiguredThenReturnsSuccessfulResult() {
		DelegatingOAuth2TokenValidator<OAuth2Token> tokenValidator = new DelegatingOAuth2TokenValidator<>();
		OAuth2Token token = mock(OAuth2Token.class);
		assertThat(tokenValidator.validate(token).hasErrors()).isFalse();
	}

	@Test
	public void validateWhenAnyValidatorFailsThenReturnsFailureResultContainingDetailFromFailingValidator() {
		OAuth2TokenValidator<OAuth2Token> success = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<OAuth2Token> failure = mock(OAuth2TokenValidator.class);
		given(success.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.success());
		given(failure.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.failure(DETAIL));
		DelegatingOAuth2TokenValidator<OAuth2Token> tokenValidator = new DelegatingOAuth2TokenValidator<>(
				Arrays.asList(success, failure));
		OAuth2Token token = mock(OAuth2Token.class);
		OAuth2TokenValidatorResult result = tokenValidator.validate(token);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).containsExactly(DETAIL);
	}

	@Test
	public void validateWhenMultipleValidatorsFailThenReturnsFailureResultContainingAllDetails() {
		OAuth2TokenValidator<OAuth2Token> firstFailure = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<OAuth2Token> secondFailure = mock(OAuth2TokenValidator.class);
		OAuth2Error otherDetail = new OAuth2Error("another-error");
		given(firstFailure.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.failure(DETAIL));
		given(secondFailure.validate(any(OAuth2Token.class)))
				.willReturn(OAuth2TokenValidatorResult.failure(otherDetail));
		DelegatingOAuth2TokenValidator<OAuth2Token> tokenValidator = new DelegatingOAuth2TokenValidator<>(firstFailure,
				secondFailure);
		OAuth2Token token = mock(OAuth2Token.class);
		OAuth2TokenValidatorResult result = tokenValidator.validate(token);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).containsExactly(DETAIL, otherDetail);
	}

	@Test
	public void validateWhenAllValidatorsSucceedThenReturnsSuccessfulResult() {
		OAuth2TokenValidator<OAuth2Token> firstSuccess = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<OAuth2Token> secondSuccess = mock(OAuth2TokenValidator.class);
		given(firstSuccess.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.success());
		given(secondSuccess.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.success());
		DelegatingOAuth2TokenValidator<OAuth2Token> tokenValidator = new DelegatingOAuth2TokenValidator<>(
				Arrays.asList(firstSuccess, secondSuccess));
		OAuth2Token token = mock(OAuth2Token.class);
		OAuth2TokenValidatorResult result = tokenValidator.validate(token);
		assertThat(result.hasErrors()).isFalse();
		assertThat(result.getErrors()).isEmpty();
	}

	@Test
	public void constructorWhenInvokedWithNullValidatorListThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new DelegatingOAuth2TokenValidator<>((Collection<OAuth2TokenValidator<OAuth2Token>>) null));
	}

	@Test
	public void constructorsWhenInvokedWithSameInputsThenResultInSameOutputs() {
		OAuth2TokenValidator<OAuth2Token> firstSuccess = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<OAuth2Token> secondSuccess = mock(OAuth2TokenValidator.class);
		given(firstSuccess.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.success());
		given(secondSuccess.validate(any(OAuth2Token.class))).willReturn(OAuth2TokenValidatorResult.success());
		DelegatingOAuth2TokenValidator<OAuth2Token> firstValidator = new DelegatingOAuth2TokenValidator<>(
				Arrays.asList(firstSuccess, secondSuccess));
		DelegatingOAuth2TokenValidator<OAuth2Token> secondValidator = new DelegatingOAuth2TokenValidator<>(firstSuccess,
				secondSuccess);
		OAuth2Token token = mock(OAuth2Token.class);
		firstValidator.validate(token);
		secondValidator.validate(token);
		verify(firstSuccess, times(2)).validate(token);
		verify(secondSuccess, times(2)).validate(token);
	}

}
