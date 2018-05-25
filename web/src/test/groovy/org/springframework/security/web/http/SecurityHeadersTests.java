/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.http;

import org.junit.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class SecurityHeadersTests {

	@Test
	public void bearerTokenWhenNullThenIllegalArgumentException() {
		String bearerTokenValue = null;
		assertThatThrownBy(() -> SecurityHeaders.bearerToken(bearerTokenValue))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void bearerTokenWhenEmptyStringThenIllegalArgumentException() {
		assertThatThrownBy(() -> SecurityHeaders.bearerToken(""))
				.isInstanceOf(IllegalArgumentException.class);
	}

}
