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

package org.springframework.security.web.authentication.logout;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.header.HeaderWriter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rafiullah Hamedy
 * @author Josh Cummings
 * @see HeaderWriterLogoutHandler
 */
public class HeaderWriterLogoutHandlerTests {

	private MockHttpServletResponse response;

	private MockHttpServletRequest request;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Before
	public void setup() {
		this.response = new MockHttpServletResponse();
		this.request = new MockHttpServletRequest();
	}

	@Test
	public void constructorWhenHeaderWriterIsNullThenThrowsException() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("headerWriter cannot be null");

		new HeaderWriterLogoutHandler(null);
	}

	@Test
	public void logoutWhenHasHeaderWriterThenInvoked() {
		HeaderWriter headerWriter = mock(HeaderWriter.class);
		HeaderWriterLogoutHandler handler = new HeaderWriterLogoutHandler(headerWriter);
		handler.logout(this.request, this.response, mock(Authentication.class));

		verify(headerWriter).writeHeaders(this.request, this.response);
	}

}
