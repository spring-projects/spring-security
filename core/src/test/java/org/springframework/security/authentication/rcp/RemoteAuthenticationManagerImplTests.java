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

package org.springframework.security.authentication.rcp;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Tests {@link RemoteAuthenticationManagerImpl}.
 *
 * @author Ben Alex
 */
public class RemoteAuthenticationManagerImplTests {
	// ~ Methods
	// ========================================================================================================

	@Test(expected = RemoteAuthenticationException.class)
	public void testFailedAuthenticationReturnsRemoteAuthenticationException() {
		RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();
		AuthenticationManager am = mock(AuthenticationManager.class);
		when(am.authenticate(any(Authentication.class))).thenThrow(
				new BadCredentialsException(""));
		manager.setAuthenticationManager(am);

		manager.attemptAuthentication("rod", "password");
	}

	@Test
	public void testStartupChecksAuthenticationManagerSet() throws Exception {
		RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();

		try {
			manager.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		manager.setAuthenticationManager(mock(AuthenticationManager.class));
		manager.afterPropertiesSet();

	}

	@Test
	public void testSuccessfulAuthentication() {
		RemoteAuthenticationManagerImpl manager = new RemoteAuthenticationManagerImpl();
		AuthenticationManager am = mock(AuthenticationManager.class);
		when(am.authenticate(any(Authentication.class))).thenReturn(
				new TestingAuthenticationToken("u", "p", "A"));
		manager.setAuthenticationManager(am);

		manager.attemptAuthentication("rod", "password");
	}
}
