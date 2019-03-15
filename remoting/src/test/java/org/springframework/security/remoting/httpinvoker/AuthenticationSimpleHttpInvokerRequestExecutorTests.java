/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.remoting.httpinvoker;

import junit.framework.TestCase;


import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.remoting.httpinvoker.AuthenticationSimpleHttpInvokerRequestExecutor;

import java.io.IOException;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link AuthenticationSimpleHttpInvokerRequestExecutor}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class AuthenticationSimpleHttpInvokerRequestExecutorTests extends TestCase {

    //~ Methods ========================================================================================================

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    public void testNormalOperation() throws Exception {
        // Setup client-side context
        Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken("Aladdin", "open sesame");
        SecurityContextHolder.getContext().setAuthentication(clientSideAuthentication);

        // Create a connection and ensure our executor sets its
        // properties correctly
        AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
        HttpURLConnection conn = new MockHttpURLConnection(new URL("http://localhost/"));
        executor.prepareConnection(conn, 10);

        // Check connection properties
        // See http://www.faqs.org/rfcs/rfc1945.html section 11.1 for example
        // we are comparing against
        assertEquals("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", conn.getRequestProperty("Authorization"));
    }

    public void testNullContextHolderIsNull() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);

        // Create a connection and ensure our executor sets its
        // properties correctly
        AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
        HttpURLConnection conn = new MockHttpURLConnection(new URL("http://localhost/"));
        executor.prepareConnection(conn, 10);

        // Check connection properties (shouldn't be an Authorization header)
        assertNull(conn.getRequestProperty("Authorization"));
    }

    // SEC-1975
    public void testNullContextHolderWhenAnonymous() throws Exception {
        AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "principal",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        SecurityContextHolder.getContext().setAuthentication(anonymous);

        // Create a connection and ensure our executor sets its
        // properties correctly
        AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
        HttpURLConnection conn = new MockHttpURLConnection(new URL("http://localhost/"));
        executor.prepareConnection(conn, 10);

        // Check connection properties (shouldn't be an Authorization header)
        assertNull(conn.getRequestProperty("Authorization"));
    }

    //~ Inner Classes ==================================================================================================

    private class MockHttpURLConnection extends HttpURLConnection {
        private Map<String,String> requestProperties = new HashMap<String,String>();

        public MockHttpURLConnection(URL u) {
            super(u);
        }

        public void connect() throws IOException {
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
