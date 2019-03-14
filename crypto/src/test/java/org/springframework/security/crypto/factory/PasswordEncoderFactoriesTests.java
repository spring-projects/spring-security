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

package org.springframework.security.crypto.factory;

import org.junit.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class PasswordEncoderFactoriesTests {
	private PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	private String rawPassword = "password";

	@Test
	public void encodeWhenDefaultThenBCryptUsed() {
		String encodedPassword = this.encoder.encode(this.rawPassword);

		assertThat(encodedPassword).startsWith("{bcrypt}");
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenBCryptThenWorks() {
		String encodedPassword = "{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenLdapThenWorks() {
		String encodedPassword = "{ldap}{SSHA}igvD9lOiTXm16dmOw0YWRb9OjK2ThZvdQku2EQ==";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenMd4ThenWorks() {
		String encodedPassword = "{MD4}{KYp8/QErWyQemYazZQ8UnWWfbGbkYkVC8qMi0duoA84=}152ce09d3261d2b53cac55b2ea4d1c7a";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenMd5ThenWorks() {
		String encodedPassword = "{MD5}{aRYR+Yp2xSqtgF+vtjH6jNda6M083iEbP+zCFjLt9IA=}905e382a25eed53e22224223b3581092";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenNoopThenWorks() {
		String encodedPassword = "{noop}password";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenPbkdf2ThenWorks() {
		String encodedPassword = "{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenSCryptThenWorks() {
		String encodedPassword = "{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenSHA1ThenWorks() {
		String encodedPassword = "{SHA-1}{6581QepZz2qd8jVrT2QYPVtK8DuM2n45dVslmc3UTWc=}4f31573948ddbfb8ac9dd80107dfad13fd8f2454";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenSHA256ThenWorks() {
		String encodedPassword = "{SHA-256}{UisHp3pFSMqcqrhQsrhR+hspIG0SyMDyDW/XtY+t6nA=}a98efbaf59277bfd1837c33fd4fde67de5bcfd2205bcba0992f6fc32b03a8f88";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

	@Test
	public void matchesWhenSha256ThenWorks() {
		String encodedPassword = "{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0";
		assertThat(this.encoder.matches(this.rawPassword, encodedPassword)).isTrue();
	}

}
