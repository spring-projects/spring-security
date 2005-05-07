/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context.httpinvoker;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.SecurityContext;
import net.sf.acegisecurity.context.httpinvoker.AuthenticationSimpleHttpInvokerRequestExecutor;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.io.IOException;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.HashMap;
import java.util.Map;


/**
 * Tests {@link AuthenticationSimpleHttpInvokerRequestExecutor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationSimpleHttpInvokerRequestExecutorTests
    extends TestCase {
    //~ Constructors ===========================================================

    public AuthenticationSimpleHttpInvokerRequestExecutorTests() {
        super();
    }

    public AuthenticationSimpleHttpInvokerRequestExecutorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthenticationSimpleHttpInvokerRequestExecutorTests.class);
    }

    public void testNormalOperation() throws Exception {
        // Setup client-side context
        Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken("Aladdin",
                "open sesame");
        SecurityContext.setAuthentication(clientSideAuthentication);

        // Create a connection and ensure our executor sets its
        // properties correctly
        AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
        HttpURLConnection conn = new MockHttpURLConnection(new URL(
                    "http://localhost/"));
        executor.prepareConnection(conn, 10);

        // Check connection properties
        // See http://www.faqs.org/rfcs/rfc1945.html section 11.1 for example
        // we are comparing against
        assertEquals("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            conn.getRequestProperty("Authorization"));

        SecurityContext.setAuthentication(null);
    }

    public void testNullContextHolderIsNull() throws Exception {
        SecurityContext.setAuthentication(null);

        // Create a connection and ensure our executor sets its
        // properties correctly
        AuthenticationSimpleHttpInvokerRequestExecutor executor = new AuthenticationSimpleHttpInvokerRequestExecutor();
        HttpURLConnection conn = new MockHttpURLConnection(new URL(
                    "http://localhost/"));
        executor.prepareConnection(conn, 10);

        // Check connection properties (shouldn't be an Authorization header)
        assertNull(conn.getRequestProperty("Authorization"));
    }

    //~ Inner Classes ==========================================================

    private class MockHttpURLConnection extends HttpURLConnection {
        private Map requestProperties = new HashMap();

        public MockHttpURLConnection(URL u) {
            super(u);
        }

        public void setRequestProperty(String key, String value) {
            requestProperties.put(key, value);
        }

        public String getRequestProperty(String key) {
            return (String) requestProperties.get(key);
        }

        public void connect() throws IOException {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public void disconnect() {
            throw new UnsupportedOperationException("mock not implemented");
        }

        public boolean usingProxy() {
            throw new UnsupportedOperationException("mock not implemented");
        }
    }
}
