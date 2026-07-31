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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2PushedAuthorizationRequestUri}.
 *
 * @author Josh Cummings
 */
public class OAuth2PushedAuthorizationRequestUriTests {

	@Test
	public void parseWhenValidRequestUriThenReturnsExpectedValues() {
		String state = "abcXYZ123-abcXYZ123";
		long epochMilli = 1700000000000L;
		String requestUri = "urn:ietf:params:oauth:request_uri:" + state + "___" + epochMilli;

		OAuth2PushedAuthorizationRequestUri parsed = OAuth2PushedAuthorizationRequestUri.parse(requestUri);

		assertThat(parsed.getRequestUri()).isEqualTo(requestUri);
		assertThat(parsed.getState()).isEqualTo(state + "___" + epochMilli);
		assertThat(parsed.getExpiresAt()).isEqualTo(Instant.ofEpochMilli(epochMilli));
	}

	@Test
	public void createWhenParsedThenReturnsEquivalentValues() {
		Instant expiresAt = Instant.ofEpochMilli(1700000000000L);

		OAuth2PushedAuthorizationRequestUri created = OAuth2PushedAuthorizationRequestUri.create(expiresAt);
		OAuth2PushedAuthorizationRequestUri parsed = OAuth2PushedAuthorizationRequestUri.parse(created.getRequestUri());

		assertThat(parsed.getRequestUri()).isEqualTo(created.getRequestUri());
		assertThat(parsed.getState()).isEqualTo(created.getState());
		assertThat(parsed.getExpiresAt()).isEqualTo(created.getExpiresAt());
	}

}
