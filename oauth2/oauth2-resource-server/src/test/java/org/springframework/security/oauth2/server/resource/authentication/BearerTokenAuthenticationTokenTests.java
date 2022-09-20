/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link BearerTokenAuthenticationToken}
 *
 * @author Josh Cummings
 */
public class BearerTokenAuthenticationTokenTests {

	@Test
	public void constructorWhenTokenIsNullThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new BearerTokenAuthenticationToken(null))
				.withMessageContaining("token cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenTokenIsEmptyThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new BearerTokenAuthenticationToken(""))
				.withMessageContaining("token cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenTokenHasValueThenConstructedCorrectly() {
		BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken("token");
		assertThat(token.getToken()).isEqualTo("token");
		assertThat(token.getPrincipal()).isEqualTo("token");
		assertThat(token.getCredentials()).isEqualTo("token");
	}

}
