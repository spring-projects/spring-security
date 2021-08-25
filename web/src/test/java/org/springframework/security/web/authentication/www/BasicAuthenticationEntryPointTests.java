/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.www;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.DisabledException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link BasicAuthenticationEntryPoint}.
 *
 * @author Ben Alex
 */
public class BasicAuthenticationEntryPointTests {

	@Test
	public void testDetectsMissingRealmName() {
		BasicAuthenticationEntryPoint ep = new BasicAuthenticationEntryPoint();
		assertThatIllegalArgumentException().isThrownBy(ep::afterPropertiesSet)
				.withMessage("realmName must be specified");
	}

	@Test
	public void testGettersSetters() {
		BasicAuthenticationEntryPoint ep = new BasicAuthenticationEntryPoint();
		ep.setRealmName("realm");
		assertThat(ep.getRealmName()).isEqualTo("realm");
	}

	@Test
	public void testNormalOperation() throws Exception {
		BasicAuthenticationEntryPoint ep = new BasicAuthenticationEntryPoint();
		ep.setRealmName("hello");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		// ep.afterPropertiesSet();
		ep.commence(request, response, new DisabledException("These are the jokes kid"));
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getErrorMessage()).isEqualTo(HttpStatus.UNAUTHORIZED.getReasonPhrase());
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Basic realm=\"hello\"");
	}

}
