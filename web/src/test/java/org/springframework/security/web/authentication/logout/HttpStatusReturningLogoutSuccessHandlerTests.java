/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.web.authentication.logout;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 * @author Gunnar Hillert
 */
public class HttpStatusReturningLogoutSuccessHandlerTests {

	@Test
	public void testDefaultHttpStatusBeingReturned() throws Exception {
		final HttpStatusReturningLogoutSuccessHandler lsh = new HttpStatusReturningLogoutSuccessHandler();

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		lsh.onLogoutSuccess(request, response, mock(Authentication.class));

		assertNull(request.getSession(false));
		assertNull(response.getRedirectedUrl());
		assertNull(response.getForwardedUrl());
		assertEquals(HttpStatus.OK.value(), response.getStatus());
	}

	@Test
	public void testCustomHttpStatusBeingReturned() throws Exception {
		final HttpStatusReturningLogoutSuccessHandler lsh = new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT);

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		lsh.onLogoutSuccess(request, response, mock(Authentication.class));

		assertNull(request.getSession(false));
		assertNull(response.getRedirectedUrl());
		assertNull(response.getForwardedUrl());
		assertEquals(HttpStatus.NO_CONTENT.value(), response.getStatus());
	}

	@Test
	public void testThatSettNullHttpStatusThrowsException() throws Exception {

		try {
			new HttpStatusReturningLogoutSuccessHandler(null);
		}
		catch (IllegalArgumentException e) {
			assertEquals("The provided HttpStatus must not be null.", e.getMessage());
			return;
		}

		Assert.fail("Expected an IllegalArgumentException to be thrown.");
	}

}
