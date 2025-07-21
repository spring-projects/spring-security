/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.access;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

@ExtendWith(MockitoExtension.class)
public class HttpStatusAccessDeniedHandlerTests {

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	private HttpStatus httpStatus = HttpStatus.FORBIDDEN;

	private HttpStatusAccessDeniedHandler handler = new HttpStatusAccessDeniedHandler(this.httpStatus);

	private AccessDeniedException exception = new AccessDeniedException("Forbidden");

	@Test
	public void constructorHttpStatusWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new HttpStatusAccessDeniedHandler(null));
	}

	@Test
	public void commenceThenStatusSet() throws IOException, ServletException {
		this.response = new MockHttpServletResponse();
		this.handler.handle(this.request, this.response, this.exception);
		assertThat(this.response.getStatus()).isEqualTo(this.httpStatus.value());
	}

}
