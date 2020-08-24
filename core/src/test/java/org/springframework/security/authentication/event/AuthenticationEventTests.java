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

package org.springframework.security.authentication.event;

import org.junit.Test;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link AbstractAuthenticationEvent} and its subclasses.
 *
 * @author Ben Alex
 */
public class AuthenticationEventTests {

	private Authentication getAuthentication() {
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("Principal",
				"Credentials");
		authentication.setDetails("127.0.0.1");
		return authentication;
	}

	@Test
	public void testAbstractAuthenticationEvent() {
		Authentication auth = getAuthentication();
		AbstractAuthenticationEvent event = new AuthenticationSuccessEvent(auth);
		assertThat(event.getAuthentication()).isEqualTo(auth);
	}

	@Test
	public void testAbstractAuthenticationFailureEvent() {
		Authentication auth = getAuthentication();
		AuthenticationException exception = new DisabledException("TEST");
		AbstractAuthenticationFailureEvent event = new AuthenticationFailureDisabledEvent(auth, exception);
		assertThat(event.getAuthentication()).isEqualTo(auth);
		assertThat(event.getException()).isEqualTo(exception);
	}

	@Test
	public void testRejectsNullAuthentication() {
		AuthenticationException exception = new DisabledException("TEST");
		try {
			new AuthenticationFailureDisabledEvent(null, exception);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void testRejectsNullAuthenticationException() {
		try {
			new AuthenticationFailureDisabledEvent(getAuthentication(), null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

}
