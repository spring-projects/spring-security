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

package org.springframework.security.docs.features.authentication.password4jballooning;

import com.password4j.BalloonHashingFunction;
import org.junit.jupiter.api.Test;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password4j.BalloonHashingPassword4jPasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class BallooningHashingUsageTests {

	@Test
	void defaultParams() {
		// tag::default-params[]
		PasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder();
		String result = encoder.encode("myPassword");
		assertThat(encoder.matches("myPassword", result)).isTrue();
		// end::default-params[]
	}

	@Test
	void customParameters() {
		// tag::custom-params[]
		BalloonHashingFunction ballooningHashingFn =
			BalloonHashingFunction.getInstance("SHA-256", 1024, 3, 4, 3);
		PasswordEncoder encoder = new BalloonHashingPassword4jPasswordEncoder(ballooningHashingFn);
		String result = encoder.encode("myPassword");
		assertThat(encoder.matches("myPassword", result)).isTrue();
		// end::custom-params[]
	}

}
