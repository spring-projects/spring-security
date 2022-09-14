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

package org.springframework.security.crypto.password;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @author Michael Simons
 * @author heowc
 * @author Jihoon Cha
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingPasswordEncoderTests {

	@Mock
	private PasswordEncoder bcrypt;

	@Mock
	private PasswordEncoder noop;

	@Mock
	private PasswordEncoder invalidId;

	private String bcryptId = "bcrypt";

	private String rawPassword = "password";

	private String encodedPassword = "ENCODED-PASSWORD";

	private String bcryptEncodedPassword = "{bcrypt}" + this.encodedPassword;

	private String noopEncodedPassword = "{noop}" + this.encodedPassword;

	private Map<String, PasswordEncoder> delegates;

	private DelegatingPasswordEncoder passwordEncoder;

	private DelegatingPasswordEncoder onlySuffixPasswordEncoder;

	@BeforeEach
	public void setup() {
		this.delegates = new HashMap<>();
		this.delegates.put(this.bcryptId, this.bcrypt);
		this.delegates.put("noop", this.noop);
		this.passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);

		this.onlySuffixPasswordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "", "$");
	}

	@Test
	public void constructorWhenIdForEncodeNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingPasswordEncoder(null, this.delegates));
	}

	@Test
	public void constructorWhenIdForEncodeDoesNotExistThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId + "INVALID", this.delegates));
	}

	@Test
	public void constructorWhenPrefixIsNull() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates, null, "$"));
	}

	@Test
	public void constructorWhenSuffixIsNull() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "$", null));
	}

	@Test
	public void constructorWhenPrefixIsEmpty() {
		assertThat(new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "", "$")).isNotNull();
	}

	@Test
	public void constructorWhenSuffixIsEmpty() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "$", ""));
	}

	@Test
	public void constructorWhenPrefixAndSuffixAreEmpty() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "", ""));
	}

	@Test
	public void constructorWhenIdContainsPrefixThenIllegalArgumentException() {
		this.delegates.put('{' + this.bcryptId, this.bcrypt);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates));
	}

	@Test
	public void constructorWhenIdContainsSuffixThenIllegalArgumentException() {
		this.delegates.put(this.bcryptId + '$', this.bcrypt);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "", "$"));
	}

	@Test
	public void constructorWhenPrefixContainsSuffixThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingPasswordEncoder(this.bcryptId, this.delegates, "$", "$"));
	}

	@Test
	public void setDefaultPasswordEncoderForMatchesWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.passwordEncoder.setDefaultPasswordEncoderForMatches(null));
	}

	@Test
	public void matchesWhenCustomDefaultPasswordEncoderForMatchesThenDelegates() {
		String encodedPassword = "{unmapped}" + this.rawPassword;
		this.passwordEncoder.setDefaultPasswordEncoderForMatches(this.invalidId);
		assertThat(this.passwordEncoder.matches(this.rawPassword, encodedPassword)).isFalse();
		verify(this.invalidId).matches(this.rawPassword, encodedPassword);
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void encodeWhenValidThenUsesIdForEncode() {
		given(this.bcrypt.encode(this.rawPassword)).willReturn(this.encodedPassword);
		assertThat(this.passwordEncoder.encode(this.rawPassword)).isEqualTo(this.bcryptEncodedPassword);
	}

	@Test
	public void encodeWhenValidBySpecifyDelegatingPasswordEncoderThenUsesIdForEncode() {
		given(this.bcrypt.encode(this.rawPassword)).willReturn(this.encodedPassword);
		assertThat(this.onlySuffixPasswordEncoder.encode(this.rawPassword)).isEqualTo("bcrypt$" + this.encodedPassword);
	}

	@Test
	public void matchesWhenBCryptThenDelegatesToBCrypt() {
		given(this.bcrypt.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.passwordEncoder.matches(this.rawPassword, this.bcryptEncodedPassword)).isTrue();
		verify(this.bcrypt).matches(this.rawPassword, this.encodedPassword);
		verifyNoMoreInteractions(this.noop);
	}

	@Test
	public void matchesWhenBCryptBySpecifyDelegatingPasswordEncoderThenDelegatesToBCrypt() {
		given(this.bcrypt.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.onlySuffixPasswordEncoder.matches(this.rawPassword, "bcrypt$" + this.encodedPassword)).isTrue();
		verify(this.bcrypt).matches(this.rawPassword, this.encodedPassword);
		verifyNoMoreInteractions(this.noop);
	}

	@Test
	public void matchesWhenNoopThenDelegatesToNoop() {
		given(this.noop.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.passwordEncoder.matches(this.rawPassword, this.noopEncodedPassword)).isTrue();
		verify(this.noop).matches(this.rawPassword, this.encodedPassword);
		verifyNoMoreInteractions(this.bcrypt);
	}

	@Test
	public void matchesWhenUnMappedThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "{unmapped}" + this.rawPassword))
				.withMessage("There is no PasswordEncoder mapped for the id \"unmapped\"");
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoClosingPrefixStringThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "{bcrypt" + this.rawPassword))
				.withMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoStartingPrefixStringThenFalse() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "bcrypt}" + this.rawPassword))
				.withMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoIdStringThenFalse() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "{}" + this.rawPassword))
				.withMessage("There is no PasswordEncoder mapped for the id \"\"");
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenPrefixInMiddleThenFalse() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> this.passwordEncoder.matches(this.rawPassword, "invalid" + this.bcryptEncodedPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.withMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenIdIsNullThenFalse() {
		this.delegates = new Hashtable<>(this.delegates);
		DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> passwordEncoder.matches(this.rawPassword, this.rawPassword))
				.withMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNullIdThenDelegatesToInvalidId() {
		this.delegates.put(null, this.invalidId);
		this.passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);
		given(this.invalidId.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.passwordEncoder.matches(this.rawPassword, this.encodedPassword)).isTrue();
		verify(this.invalidId).matches(this.rawPassword, this.encodedPassword);
		verifyNoMoreInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenRawPasswordNotNullAndEncodedPasswordNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, null));
	}

	@Test
	public void upgradeEncodingWhenEncodedPasswordNullThenTrue() {
		assertThat(this.passwordEncoder.upgradeEncoding(null)).isTrue();
	}

	@Test
	public void upgradeEncodingWhenNullIdThenTrue() {
		assertThat(this.passwordEncoder.upgradeEncoding(this.encodedPassword)).isTrue();
	}

	@Test
	public void upgradeEncodingWhenIdInvalidFormatThenTrue() {
		assertThat(this.passwordEncoder.upgradeEncoding("{bcrypt" + this.encodedPassword)).isTrue();
	}

	@Test
	public void upgradeEncodingWhenSameIdAndEncoderFalseThenEncoderDecidesFalse() {
		assertThat(this.passwordEncoder.upgradeEncoding(this.bcryptEncodedPassword)).isFalse();
		verify(this.bcrypt).upgradeEncoding(this.encodedPassword);
	}

	@Test
	public void upgradeEncodingWhenSameIdAndEncoderTrueThenEncoderDecidesTrue() {
		given(this.bcrypt.upgradeEncoding(any())).willReturn(true);
		assertThat(this.passwordEncoder.upgradeEncoding(this.bcryptEncodedPassword)).isTrue();
		verify(this.bcrypt).upgradeEncoding(this.encodedPassword);
	}

	@Test
	public void upgradeEncodingWhenDifferentIdThenTrue() {
		assertThat(this.passwordEncoder.upgradeEncoding(this.noopEncodedPassword)).isTrue();
		verifyNoMoreInteractions(this.bcrypt);
	}

}
