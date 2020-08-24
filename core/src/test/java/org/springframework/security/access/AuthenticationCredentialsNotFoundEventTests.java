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

package org.springframework.security.access;

import org.junit.Test;

import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.util.SimpleMethodInvocation;

/**
 * Tests {@link AuthenticationCredentialsNotFoundEvent}.
 *
 * @author Ben Alex
 */
public class AuthenticationCredentialsNotFoundEventTests {

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNulls() {
		new AuthenticationCredentialsNotFoundEvent(null, SecurityConfig.createList("TEST"),
				new AuthenticationCredentialsNotFoundException("test"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNulls2() {
		new AuthenticationCredentialsNotFoundEvent(new SimpleMethodInvocation(), null,
				new AuthenticationCredentialsNotFoundException("test"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNulls3() {
		new AuthenticationCredentialsNotFoundEvent(new SimpleMethodInvocation(), SecurityConfig.createList("TEST"),
				null);
	}

}
