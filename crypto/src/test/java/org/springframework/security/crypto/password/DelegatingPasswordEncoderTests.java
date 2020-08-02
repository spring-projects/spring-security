/*
 * Copyright 2002-2017 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 * @author Michael Simons
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
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

	@Before
	public void setup() {
		this.delegates = new HashMap<>();
		this.delegates.put(this.bcryptId, this.bcrypt);
		this.delegates.put("noop", this.noop);
		this.passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenIdForEncodeNullThenIllegalArgumentException() {
		new DelegatingPasswordEncoder(null, this.delegates);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenIdForEncodeDoesNotExistThenIllegalArgumentException() {
		new DelegatingPasswordEncoder(this.bcryptId + "INVALID", this.delegates);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setDefaultPasswordEncoderForMatchesWhenNullThenIllegalArgumentException() {
		this.passwordEncoder.setDefaultPasswordEncoderForMatches(null);
	}

	@Test
	public void matchesWhenCustomDefaultPasswordEncoderForMatchesThenDelegates() {
		String encodedPassword = "{unmapped}" + this.rawPassword;
		this.passwordEncoder.setDefaultPasswordEncoderForMatches(this.invalidId);
		assertThat(this.passwordEncoder.matches(this.rawPassword, encodedPassword)).isFalse();
		verify(this.invalidId).matches(this.rawPassword, encodedPassword);
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void encodeWhenValidThenUsesIdForEncode() {
		given(this.bcrypt.encode(this.rawPassword)).willReturn(this.encodedPassword);
		assertThat(this.passwordEncoder.encode(this.rawPassword)).isEqualTo(this.bcryptEncodedPassword);
	}

	@Test
	public void matchesWhenBCryptThenDelegatesToBCrypt() {
		given(this.bcrypt.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.passwordEncoder.matches(this.rawPassword, this.bcryptEncodedPassword)).isTrue();
		verify(this.bcrypt).matches(this.rawPassword, this.encodedPassword);
		verifyZeroInteractions(this.noop);
	}

	@Test
	public void matchesWhenNoopThenDelegatesToNoop() {
		given(this.noop.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.passwordEncoder.matches(this.rawPassword, this.noopEncodedPassword)).isTrue();
		verify(this.noop).matches(this.rawPassword, this.encodedPassword);
		verifyZeroInteractions(this.bcrypt);
	}

	@Test
	public void matchesWhenUnMappedThenIllegalArgumentException() {
		assertThatThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "{unmapped}" + this.rawPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("There is no PasswordEncoder mapped for the id \"unmapped\"");
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoClosingPrefixStringThenIllegalArgumentExcetion() {
		assertThatThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "{bcrypt" + this.rawPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoStartingPrefixStringThenFalse() {
		assertThatThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "bcrypt}" + this.rawPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoIdStringThenFalse() {
		assertThatThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "{}" + this.rawPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("There is no PasswordEncoder mapped for the id \"\"");
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenPrefixInMiddleThenFalse() {
		assertThatThrownBy(() -> this.passwordEncoder.matches(this.rawPassword, "invalid" + this.bcryptEncodedPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenIdIsNullThenFalse() {
		this.delegates = new Hashtable<>(this.delegates);
		DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);
		assertThatThrownBy(() -> passwordEncoder.matches(this.rawPassword, this.rawPassword))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNullIdThenDelegatesToInvalidId() {
		this.delegates.put(null, this.invalidId);
		this.passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);
		given(this.invalidId.matches(this.rawPassword, this.encodedPassword)).willReturn(true);
		assertThat(this.passwordEncoder.matches(this.rawPassword, this.encodedPassword)).isTrue();
		verify(this.invalidId).matches(this.rawPassword, this.encodedPassword);
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test(expected = IllegalArgumentException.class)
	public void matchesWhenRawPasswordNotNullAndEncodedPasswordNullThenThrowsIllegalArgumentException() {
		this.passwordEncoder.matches(this.rawPassword, null);
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
		verifyZeroInteractions(this.bcrypt);
	}

}
