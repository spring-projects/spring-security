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

package org.springframework.security.web.server.authentication;

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Eric Deandrea
 * @since 5.1
 */
public class HttpStatusServerEntryPointTests {

	private MockServerHttpRequest request;

	private MockServerWebExchange exchange;

	private AuthenticationException authException;

	private HttpStatusServerEntryPoint entryPoint;

	@Before
	public void setup() {
		this.request = MockServerHttpRequest.get("/").build();
		this.exchange = MockServerWebExchange.from(this.request);
		this.authException = new AuthenticationException("") {
		};
		this.entryPoint = new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void constructorNullStatus() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new HttpStatusServerEntryPoint(null))
				.withMessage("httpStatus cannot be null");
	}

	@Test
	public void unauthorized() {
		this.entryPoint.commence(this.exchange, this.authException).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

}
