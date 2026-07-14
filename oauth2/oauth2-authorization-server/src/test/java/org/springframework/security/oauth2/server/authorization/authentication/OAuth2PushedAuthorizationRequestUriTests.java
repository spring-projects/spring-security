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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2PushedAuthorizationRequestUri}.
 *
 * @author Andrey Litvitski
 */
public class OAuth2PushedAuthorizationRequestUriTests {

	@Test
	public void parseWhenStateContainsDelimiterThenParsesSuccessfully() {
		String state = "xXMGJTZwzXIFL8i_DFu_EM8IeWC___frCWjpiF2q-xs=";
		long epochMillis = 1781670640281L;
		String requestUri = "urn:ietf:params:oauth:request_uri:" + state + "___" + epochMillis;
		OAuth2PushedAuthorizationRequestUri parsedUri = OAuth2PushedAuthorizationRequestUri.parse(requestUri);

		assertThat(parsedUri.getRequestUri()).isEqualTo(requestUri);
		assertThat(parsedUri.getState()).isEqualTo(state + "___" + epochMillis);
		assertThat(parsedUri.getExpiresAt()).isEqualTo(Instant.ofEpochMilli(epochMillis));
	}

}
