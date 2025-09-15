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

package org.springframework.security.docs.features.authentication.password4jpbkdf2;

import com.password4j.PBKDF2Function;
import com.password4j.types.Hmac;
import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class Pbkdf2UsageTests {

	@Test
	void defaultParams() {
		// tag::default-params[]
		PasswordEncoder encoder = new Pbkdf2Password4jPasswordEncoder();
		String result = encoder.encode("myPassword");
		assertThat(encoder.matches("myPassword", result)).isTrue();
		// end::default-params[]
	}

	@Test
	void customParameters() {
		// tag::custom-params[]
		PBKDF2Function pbkdf2Fn = PBKDF2Function.getInstance(Hmac.SHA256, 100000, 256);
		PasswordEncoder encoder = new Pbkdf2Password4jPasswordEncoder(pbkdf2Fn);
		String result = encoder.encode("myPassword");
		assertThat(encoder.matches("myPassword", result)).isTrue();
		// end::custom-params[]
	}

}
