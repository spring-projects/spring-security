/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.io.IOException;

import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests the {@link HttpStatusReturningAuthenticationFailureHandler}.
 *
 * @author Matthias Luppi
 */
public class HttpStatusReturningAuthenticationFailureHandlerTests {

	@Test
	public void defaultHttpStatusIsReturned() throws IOException {
		final HttpStatusReturningAuthenticationFailureHandler afh = new HttpStatusReturningAuthenticationFailureHandler();
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		afh.onAuthenticationFailure(request, response, new BadCredentialsException("message"));
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		assertThat(response.getRedirectedUrl()).isNull();
		assertThat(response.getForwardedUrl()).isNull();
	}

	@Test
	public void customHttpStatusIsReturned() throws IOException {
		final HttpStatusReturningAuthenticationFailureHandler afh = new HttpStatusReturningAuthenticationFailureHandler(
				HttpStatus.CONFLICT);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		afh.onAuthenticationFailure(request, response, new BadCredentialsException("message"));
		assertThat(response.getStatus()).isEqualTo(HttpStatus.CONFLICT.value());
		assertThat(response.getRedirectedUrl()).isNull();
		assertThat(response.getForwardedUrl()).isNull();
	}

	@Test
	public void nullStatusCodeThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new HttpStatusReturningAuthenticationFailureHandler(null))
				.withMessage("The provided HttpStatus must not be null.");
	}

}
