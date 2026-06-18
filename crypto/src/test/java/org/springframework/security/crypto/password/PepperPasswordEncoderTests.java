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

package org.springframework.security.crypto.password;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link PepperPasswordEncoder}.
 *
 * @author KoreaNirsa
 */
@ExtendWith(MockitoExtension.class)
class PepperPasswordEncoderTests extends AbstractPasswordEncoderValidationTests {

	private static final String PEPPER = "server-side-secret";

	private static final String OTHER_PEPPER = "other-server-side-secret";

	private static final String RAW_PASSWORD = "password";

	private static final String PEPPERED_PASSWORD = RAW_PASSWORD + PEPPER;

	private static final String ENCODED_PASSWORD = "encoded-password";

	@Mock
	private PasswordEncoder delegate;

	@BeforeEach
	void setup() {
		setEncoder(new PepperPasswordEncoder(this.delegate, PEPPER));
	}

	@Test
	void constructorWhenPasswordEncoderNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PepperPasswordEncoder(null, PEPPER))
			.withMessage("passwordEncoder cannot be null");
	}

	@Test
	void constructorWhenPepperNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PepperPasswordEncoder(this.delegate, null))
			.withMessage("pepper cannot be null");
	}

	@Test
	void constructorWhenPepperEmptyThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PepperPasswordEncoder(this.delegate, ""))
			.withMessage("pepper cannot be empty");
	}

	@Test
	void encodeWhenValidThenDelegatesPepperedPassword() {
		given(this.delegate.encode(PEPPERED_PASSWORD)).willReturn(ENCODED_PASSWORD);

		assertThat(getEncoder().encode(RAW_PASSWORD)).isEqualTo(ENCODED_PASSWORD);

		verify(this.delegate).encode(PEPPERED_PASSWORD);
	}

	@Test
	void matchesWhenValidThenDelegatesPepperedPassword() {
		given(this.delegate.matches(PEPPERED_PASSWORD, ENCODED_PASSWORD)).willReturn(true);

		assertThat(getEncoder().matches(RAW_PASSWORD, ENCODED_PASSWORD)).isTrue();

		verify(this.delegate).matches(PEPPERED_PASSWORD, ENCODED_PASSWORD);
	}

	@Test
	void matchesWhenDelegateDoesNotMatchThenFalse() {
		given(this.delegate.matches(PEPPERED_PASSWORD, ENCODED_PASSWORD)).willReturn(false);

		assertThat(getEncoder().matches(RAW_PASSWORD, ENCODED_PASSWORD)).isFalse();

		verify(this.delegate).matches(PEPPERED_PASSWORD, ENCODED_PASSWORD);
	}

	@Test
	void matchesWhenPepperDifferentThenFalse() {
		PasswordEncoder delegate = NoOpPasswordEncoder.getInstance();
		PasswordEncoder encoder = new PepperPasswordEncoder(delegate, PEPPER);
		PasswordEncoder otherEncoder = new PepperPasswordEncoder(delegate, OTHER_PEPPER);
		String encodedPassword = encoder.encode(RAW_PASSWORD);

		assertThat(encoder.matches(RAW_PASSWORD, encodedPassword)).isTrue();
		assertThat(otherEncoder.matches(RAW_PASSWORD, encodedPassword)).isFalse();
	}

	@Test
	void upgradeEncodingWhenValidThenDelegatesEncodedPassword() {
		given(this.delegate.upgradeEncoding(ENCODED_PASSWORD)).willReturn(true);

		assertThat(getEncoder().upgradeEncoding(ENCODED_PASSWORD)).isTrue();

		verify(this.delegate).upgradeEncoding(ENCODED_PASSWORD);
		verifyNoMoreInteractions(this.delegate);
	}

}
