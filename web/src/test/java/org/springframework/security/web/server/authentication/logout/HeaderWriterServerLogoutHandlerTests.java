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

package org.springframework.security.web.server.authentication.logout;

import org.junit.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.header.ServerHttpHeadersWriter;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author MD Sayem Ahmed
 * @since 5.2
 */
public class HeaderWriterServerLogoutHandlerTests {

	@Test
	public void constructorWhenHeadersWriterIsNullThenExceptionThrown() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> new HeaderWriterServerLogoutHandler(null));
	}

	@Test
	public void logoutWhenInvokedThenWritesResponseHeaders() {
		ServerHttpHeadersWriter headersWriter = mock(ServerHttpHeadersWriter.class);
		HeaderWriterServerLogoutHandler handler = new HeaderWriterServerLogoutHandler(headersWriter);
		ServerWebExchange serverWebExchange = mock(ServerWebExchange.class);
		WebFilterExchange filterExchange = mock(WebFilterExchange.class);
		given(filterExchange.getExchange()).willReturn(serverWebExchange);
		Authentication authentication = mock(Authentication.class);

		handler.logout(filterExchange, authentication);

		verify(headersWriter).writeHttpHeaders(serverWebExchange);
	}

}
