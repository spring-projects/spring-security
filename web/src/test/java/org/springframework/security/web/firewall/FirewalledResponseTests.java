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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import javax.servlet.http.Cookie;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @author Gabriel Lavoie
 */
public class FirewalledResponseTests {
	private MockHttpServletResponse response = new MockHttpServletResponse();
	private FirewalledResponse fwResponse = new FirewalledResponse(response);

	@Rule
	public ExpectedException expectedException = ExpectedException.none();

	@Test
	public void acceptRedirectLocationWithoutCRLF() throws Exception {
		fwResponse.sendRedirect("/theURL");
		assertThat(response.getRedirectedUrl()).isEqualTo("/theURL");
	}

	@Test
	public void validateNullSafetyForRedirectLocation() throws Exception {
		// Exception from MockHttpServletResponse, exception not described in servlet spec.
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Redirect URL must not be null");

		fwResponse.sendRedirect(null);
	}

	@Test
	public void rejectsRedirectLocationContainingCRLF() throws Exception {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Invalid characters (CR/LF)");

		fwResponse.sendRedirect("/theURL\r\nsomething");
	}

	@Test
	public void acceptHeaderValueWithoutCRLF() throws Exception {
		fwResponse.addHeader("foo", "bar");
		assertThat(response.getHeader("foo")).isEqualTo("bar");
	}

	@Test
	public void validateNullSafetyForHeaderValue() throws Exception {
		// Exception from MockHttpServletResponse, exception not described in servlet spec.
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Header value must not be null");

		fwResponse.addHeader("foo", null);
	}

	@Test
	public void rejectHeaderValueContainingCRLF() {
		expectCRLFValidationException();

		fwResponse.addHeader("foo", "abc\r\nContent-Length:100");
	}

	@Test
	public void rejectHeaderNameContainingCRLF() {
		expectCRLFValidationException();

		fwResponse.addHeader("abc\r\nContent-Length:100", "bar");
	}

	@Test
	public void acceptCookieWithoutCRLF() {
		Cookie cookie = new Cookie("foo", "bar");
		cookie.setPath("/foobar");
		cookie.setDomain("foobar");
		cookie.setComment("foobar");

		fwResponse.addCookie(cookie);
	}

	@Test
	public void rejectCookieNameContainingCRLF() {
		// This one is thrown by the Cookie class constructor from javax.servlet-api,
		// no need to cover in FirewalledResponse.
		expectedException.expect(IllegalArgumentException.class);
		Cookie cookie = new Cookie("foo\r\nbar", "bar");
	}

	@Test
	public void rejectCookieValueContainingCRLF() {
		expectCRLFValidationException();

		Cookie cookie = new Cookie("foo", "foo\r\nbar");
		fwResponse.addCookie(cookie);
	}

	@Test
	public void rejectCookiePathContainingCRLF() {
		expectCRLFValidationException();

		Cookie cookie = new Cookie("foo", "bar");
		cookie.setPath("/foo\r\nbar");

		fwResponse.addCookie(cookie);
	}

	@Test
	public void rejectCookieDomainContainingCRLF() {
		expectCRLFValidationException();

		Cookie cookie = new Cookie("foo", "bar");
		cookie.setDomain("foo\r\nbar");

		fwResponse.addCookie(cookie);
	}

	@Test
	public void rejectCookieCommentContainingCRLF() {
		expectCRLFValidationException();

		Cookie cookie = new Cookie("foo", "bar");
		cookie.setComment("foo\r\nbar");

		fwResponse.addCookie(cookie);
	}

	@Test
	public void rejectAnyLineEndingInNameAndValue() {
		validateLineEnding("foo", "foo\rbar");
		validateLineEnding("foo", "foo\r\nbar");
		validateLineEnding("foo", "foo\nbar");

		validateLineEnding("foo\rbar", "bar");
		validateLineEnding("foo\r\nbar", "bar");
		validateLineEnding("foo\nbar", "bar");
	}

	private void expectCRLFValidationException() {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Invalid characters (CR/LF)");
	}

	private void validateLineEnding(String name, String value) {
		try {
			fwResponse.validateCRLF(name, value);
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
	}
}
