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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

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
		this.delegates = new HashMap<String, PasswordEncoder>();
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
		when(this.bcrypt.encode(this.rawPassword)).thenReturn(this.encodedPassword);

		assertThat(this.passwordEncoder.encode(this.rawPassword)).isEqualTo(this.bcryptEncodedPassword);
	}

	@Test
	public void matchesWhenBCryptThenDelegatesToBCrypt() {
		when(this.bcrypt.matches(this.rawPassword, this.encodedPassword)).thenReturn(true);

		assertThat(this.passwordEncoder.matches(this.rawPassword, this.bcryptEncodedPassword)).isTrue();

		verify(this.bcrypt).matches(this.rawPassword, this.encodedPassword);
		verifyZeroInteractions(this.noop);
	}

	@Test
	public void matchesWhenNoopThenDelegatesToNoop() {
		when(this.noop.matches(this.rawPassword, this.encodedPassword)).thenReturn(true);

		assertThat(this.passwordEncoder.matches(this.rawPassword, this.noopEncodedPassword)).isTrue();

		verify(this.noop).matches(this.rawPassword, this.encodedPassword);
		verifyZeroInteractions(this.bcrypt);
	}

	@Test
	public void matchesWhenUnMappedThenIllegalArgumentException() {
		try {
			this.passwordEncoder.matches(this.rawPassword, "{unmapped}" + this.rawPassword);
			fail("Expected Exception");
		} catch(IllegalArgumentException e) {
			assertThat(e).hasMessage("There is no PasswordEncoder mapped for the id \"unmapped\"");
		}

		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoClosingPrefixStringThenIllegalArgumentExcetion() {
		try {
			this.passwordEncoder.matches(this.rawPassword, "{bcrypt" + this.rawPassword);
			fail("Expected Exception");
		} catch(IllegalArgumentException e) {
			assertThat(e).hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		}

		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoStartingPrefixStringThenFalse() {
		try {
			this.passwordEncoder.matches(this.rawPassword, "bcrypt}" + this.rawPassword);
			fail("Expected Exception");
		} catch(IllegalArgumentException e) {
			assertThat(e).hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		}

		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNoIdStringThenFalse() {
		try {
			this.passwordEncoder.matches(this.rawPassword, "{}" + this.rawPassword);
			fail("Expected Exception");
		} catch(IllegalArgumentException e) {
			assertThat(e).hasMessage("There is no PasswordEncoder mapped for the id \"\"");
		}

		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenPrefixInMiddleThenFalse() {
		try {
			this.passwordEncoder.matches(this.rawPassword, "invalid" + this.bcryptEncodedPassword);
			fail("Expected Exception");
		} catch(IllegalArgumentException e) {
			assertThat(e).hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		}

		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenIdIsNullThenFalse() {
		this.delegates = new Hashtable<String, PasswordEncoder>(this.delegates);

		DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);

		try {
			passwordEncoder.matches(this.rawPassword, this.rawPassword);
			fail("Expected Exception");
		} catch(IllegalArgumentException e) {
			assertThat(e).hasMessage("There is no PasswordEncoder mapped for the id \"null\"");
		}

		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test
	public void matchesWhenNullIdThenDelegatesToInvalidId() {
		this.delegates.put(null, this.invalidId);
		this.passwordEncoder = new DelegatingPasswordEncoder(this.bcryptId, this.delegates);
		when(this.invalidId.matches(this.rawPassword, this.encodedPassword)).thenReturn(true);

		assertThat(this.passwordEncoder.matches(this.rawPassword, this.encodedPassword)).isTrue();

		verify(this.invalidId).matches(this.rawPassword, this.encodedPassword);
		verifyZeroInteractions(this.bcrypt, this.noop);
	}

	@Test(expected = IllegalArgumentException.class)
	public void matchesWhenRawPasswordNotNullAndEncodedPasswordNullThenThrowsIllegalArgumentException() {
		this.passwordEncoder.matches(this.rawPassword, null);
	}
}
