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

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for verifying {@link DelegatingOAuth2TokenValidator}
 *
 * @author Josh Cummings
 */
public class DelegatingOAuth2TokenValidatorTests {
	private static final OAuth2Error DETAIL = new OAuth2Error(
			"error", "description", "uri");

	@Test
	public void validateWhenNoValidatorsConfiguredThenReturnsSuccessfulResult() {
		DelegatingOAuth2TokenValidator<AbstractOAuth2Token> tokenValidator =
				new DelegatingOAuth2TokenValidator<>();
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);

		assertThat(tokenValidator.validate(token).hasErrors()).isFalse();
	}

	@Test
	public void validateWhenAnyValidatorFailsThenReturnsFailureResultContainingDetailFromFailingValidator() {
		OAuth2TokenValidator<AbstractOAuth2Token> success = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<AbstractOAuth2Token> failure = mock(OAuth2TokenValidator.class);

		when(success.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.success());
		when(failure.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.failure(DETAIL));

		DelegatingOAuth2TokenValidator<AbstractOAuth2Token> tokenValidator =
				new DelegatingOAuth2TokenValidator<>(Arrays.asList(success, failure));
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);

		OAuth2TokenValidatorResult result =
				tokenValidator.validate(token);

		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).containsExactly(DETAIL);
	}

	@Test
	public void validateWhenMultipleValidatorsFailThenReturnsFailureResultContainingAllDetails() {
		OAuth2TokenValidator<AbstractOAuth2Token> firstFailure = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<AbstractOAuth2Token> secondFailure = mock(OAuth2TokenValidator.class);

		OAuth2Error otherDetail = new OAuth2Error("another-error");

		when(firstFailure.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.failure(DETAIL));
		when(secondFailure.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.failure(otherDetail));

		DelegatingOAuth2TokenValidator<AbstractOAuth2Token> tokenValidator =
				new DelegatingOAuth2TokenValidator<>(firstFailure, secondFailure);
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);

		OAuth2TokenValidatorResult result =
				tokenValidator.validate(token);

		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).containsExactly(DETAIL, otherDetail);
	}

	@Test
	public void validateWhenAllValidatorsSucceedThenReturnsSuccessfulResult() {
		OAuth2TokenValidator<AbstractOAuth2Token> firstSuccess = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<AbstractOAuth2Token> secondSuccess = mock(OAuth2TokenValidator.class);

		when(firstSuccess.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.success());
		when(secondSuccess.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.success());

		DelegatingOAuth2TokenValidator<AbstractOAuth2Token> tokenValidator =
				new DelegatingOAuth2TokenValidator<>(Arrays.asList(firstSuccess, secondSuccess));
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);

		OAuth2TokenValidatorResult result =
				tokenValidator.validate(token);

		assertThat(result.hasErrors()).isFalse();
		assertThat(result.getErrors()).isEmpty();
	}

	@Test
	public void constructorWhenInvokedWithNullValidatorListThenThrowsIllegalArgumentException() {
		assertThatCode(() -> new DelegatingOAuth2TokenValidator<>
				((Collection<OAuth2TokenValidator<AbstractOAuth2Token>>) null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorsWhenInvokedWithSameInputsThenResultInSameOutputs() {
		OAuth2TokenValidator<AbstractOAuth2Token> firstSuccess = mock(OAuth2TokenValidator.class);
		OAuth2TokenValidator<AbstractOAuth2Token> secondSuccess = mock(OAuth2TokenValidator.class);

		when(firstSuccess.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.success());
		when(secondSuccess.validate(any(AbstractOAuth2Token.class)))
				.thenReturn(OAuth2TokenValidatorResult.success());

		DelegatingOAuth2TokenValidator<AbstractOAuth2Token> firstValidator =
				new DelegatingOAuth2TokenValidator<>(Arrays.asList(firstSuccess, secondSuccess));
		DelegatingOAuth2TokenValidator<AbstractOAuth2Token> secondValidator =
				new DelegatingOAuth2TokenValidator<>(firstSuccess, secondSuccess);

		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);

		firstValidator.validate(token);
		secondValidator.validate(token);

		verify(firstSuccess, times(2)).validate(token);
		verify(secondSuccess, times(2)).validate(token);
	}
}
