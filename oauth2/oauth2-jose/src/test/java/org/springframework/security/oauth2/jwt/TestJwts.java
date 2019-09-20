/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.time.Instant;
import java.util.Arrays;

public class TestJwts {
	public static Jwt.Builder jwt() {
		return Jwt.withTokenValue("token")
				.header("alg", "none")
				.audience(Arrays.asList("https://audience.example.org"))
				.expiresAt(Instant.MAX)
				.issuedAt(Instant.MIN)
				.issuer("https://issuer.example.org")
				.jti("jti")
				.notBefore(Instant.MIN)
				.subject("mock-test-subject");
	}

	public static Jwt user() {
		return jwt()
				.claim("sub", "mock-test-subject")
				.build();
	}
}
