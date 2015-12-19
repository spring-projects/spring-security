/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.jaas;

import static org.assertj.core.api.Assertions.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.jaas.SecurityContextLoginModule;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

/**
 * Tests SecurityContextLoginModule
 *
 * @author Ray Krueger
 */
public class SecurityContextLoginModuleTests {
	// ~ Instance fields
	// ================================================================================================

	private SecurityContextLoginModule module = null;
	private Subject subject = new Subject(false, new HashSet<Principal>(), new HashSet<Object>(),
			new HashSet<Object>());
	private UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("principal",
			"credentials");

	// ~ Methods
	// ========================================================================================================

	@Before
	public void setUp() throws Exception {
		module = new SecurityContextLoginModule();
		module.initialize(subject, null, null, null);
		SecurityContextHolder.clearContext();
	}

	@After
	public void tearDown() throws Exception {
		SecurityContextHolder.clearContext();
		module = null;
	}

	@Test
	public void testAbort() throws Exception {
		assertThat(module.abort()).as("Should return false, no auth is set").isFalse();
		SecurityContextHolder.getContext().setAuthentication(auth);
		module.login();
		module.commit();
		assertThat(module.abort()).isTrue();
	}
	
	@Test
	public void testLoginException() throws Exception {
		try {
			module.login();
			fail("LoginException expected, there is no Authentication in the SecurityContext");
		} catch (LoginException e) {
		}
	}

	@Test
	public void testLoginSuccess() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(auth);
		assertThat(module.login()).as("Login should succeed, there is an authentication set").isTrue();
		assertThat(module.commit()).withFailMessage("The authentication is not null, this should return true").isTrue();
		assertThat(subject.getPrincipals().contains(auth))
				.withFailMessage("Principals should contain the authentication").isTrue();
	}
	
	@Test
	public void testLogout() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(auth);
		module.login();
		assertThat(module.logout()).as("Should return true as it succeeds").isTrue();
		assertThat(module.getAuthentication()).as("Authentication should be null").isEqualTo(null);

		assertThat(subject.getPrincipals().contains(auth)).withFailMessage("Principals should not contain the authentication after logout").isFalse();
	}
	
	@Test
	public void testNullAuthenticationInSecurityContext() throws Exception {
		try {
			SecurityContextHolder.getContext().setAuthentication(null);
			module.login();
			fail("LoginException expected, the authentication is null in the SecurityContext");
		} catch (Exception e) {
		}
	}
	
	@Test
	public void testNullAuthenticationInSecurityContextIgnored() throws Exception {
		module = new SecurityContextLoginModule();

		Map<String, String> options = new HashMap<String, String>();
		options.put("ignoreMissingAuthentication", "true");

		module.initialize(subject, null, null, options);
		SecurityContextHolder.getContext().setAuthentication(null);
		assertThat(module.login()).as("Should return false and ask to be ignored").isFalse();
	}
	
	@Test
	public void testNullLogout() throws Exception {
		assertThat(module.logout()).isFalse();
	}
}
