/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.firewall;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
public class FirewalledResponseTests {

	@Test
	public void rejectsRedirectLocationContainingCRLF() throws Exception {
		MockHttpServletResponse response = new MockHttpServletResponse();
		FirewalledResponse fwResponse = new FirewalledResponse(response);

		fwResponse.sendRedirect("/theURL");
		assertThat(response.getRedirectedUrl()).isEqualTo("/theURL");

		try {
			fwResponse.sendRedirect("/theURL\r\nsomething");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
		try {
			fwResponse.sendRedirect("/theURL\rsomething");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			fwResponse.sendRedirect("/theURL\nsomething");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void rejectHeaderContainingCRLF() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		FirewalledResponse fwResponse = new FirewalledResponse(response);

		try {
			fwResponse.addHeader("foo", "abc\r\nContent-Length:100");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
		try {
			fwResponse.setHeader("foo", "abc\r\nContent-Length:100");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
	}

}
