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

package org.springframework.security.remoting.httpinvoker;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Tests {@link AuthenticationSimpleHttpInvokerRequestExecutor}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class AuthenticationSimpleHttpInvokerRequestExecutorTests {

	// ~ Methods
	// ========================================================================================================
	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testNormalOperation() throws Exception {
		// Setup client-side context
		Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken("Aladdin", "open sesame");
		SecurityContextHolder.getContext().setAuthentication(clientSideAuthentication);

		// Create a connection and ensure our executor sets its
		// properties correctly
		AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
		HttpURLConnection conn = new MockHttpURLConnection(new URL("https://localhost/"));
		executor.prepareConnection(conn, 10);

		// Check connection properties
		// See https://tools.ietf.org/html/rfc1945 section 11.1 for example
		// we are comparing against
		assertThat(conn.getRequestProperty("Authorization")).isEqualTo("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
	}

	@Test
	public void testNullContextHolderIsNull() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(null);

		// Create a connection and ensure our executor sets its
		// properties correctly
		AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
		HttpURLConnection conn = new MockHttpURLConnection(new URL("https://localhost/"));
		executor.prepareConnection(conn, 10);

		// Check connection properties (shouldn't be an Authorization header)
		assertThat(conn.getRequestProperty("Authorization")).isNull();
	}

	// SEC-1975
	@Test
	public void testNullContextHolderWhenAnonymous() throws Exception {
		AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "principal",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		SecurityContextHolder.getContext().setAuthentication(anonymous);

		// Create a connection and ensure our executor sets its
		// properties correctly
		AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
		HttpURLConnection conn = new MockHttpURLConnection(new URL("https://localhost/"));
		executor.prepareConnection(conn, 10);

		// Check connection properties (shouldn't be an Authorization header)
		assertThat(conn.getRequestProperty("Authorization")).isNull();
	}

	// ~ Inner Classes
	// ==================================================================================================

	private class MockHttpURLConnection extends HttpURLConnection {

		private Map<String, String> requestProperties = new HashMap<>();

		MockHttpURLConnection(URL u) {
			super(u);
		}

		public void connect() {
			throw new UnsupportedOperationException("mock not implemented");
		}

		public void disconnect() {
			throw new UnsupportedOperationException("mock not implemented");
		}

		public String getRequestProperty(String key) {
			return requestProperties.get(key);
		}

		public void setRequestProperty(String key, String value) {
			requestProperties.put(key, value);
		}

		public boolean usingProxy() {
			throw new UnsupportedOperationException("mock not implemented");
		}

	}

}
