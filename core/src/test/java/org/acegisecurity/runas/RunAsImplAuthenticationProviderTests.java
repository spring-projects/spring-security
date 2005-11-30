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

package org.acegisecurity.runas;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.TestingAuthenticationToken;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link RunAsImplAuthenticationProvider}.
 */
public class RunAsImplAuthenticationProviderTests extends TestCase {
    //~ Constructors ===========================================================

    public RunAsImplAuthenticationProviderTests() {
        super();
    }

    public RunAsImplAuthenticationProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RunAsImplAuthenticationProviderTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAuthenticationFailDueToWrongKey() {
        RunAsUserToken token = new RunAsUserToken("WRONG_PASSWORD", "Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, UsernamePasswordAuthenticationToken.class);
        RunAsImplAuthenticationProvider provider = new RunAsImplAuthenticationProvider();
        provider.setKey("hello_world");

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticationSuccess() {
        RunAsUserToken token = new RunAsUserToken("my_password", "Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, UsernamePasswordAuthenticationToken.class);
        RunAsImplAuthenticationProvider provider = new RunAsImplAuthenticationProvider();
        provider.setKey("my_password");

        Authentication result = provider.authenticate(token);

        if (!(result instanceof RunAsUserToken)) {
            fail("Should have returned RunAsUserToken");
        }

        RunAsUserToken resultCast = (RunAsUserToken) result;
        assertEquals("my_password".hashCode(), resultCast.getKeyHash());
    }

    public void testStartupFailsIfNoKey() throws Exception {
        RunAsImplAuthenticationProvider provider = new RunAsImplAuthenticationProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupSuccess() throws Exception {
        RunAsImplAuthenticationProvider provider = new RunAsImplAuthenticationProvider();
        provider.setKey("hello_world");
        assertEquals("hello_world", provider.getKey());
        provider.afterPropertiesSet();
        assertTrue(true);
    }

    public void testSupports() {
        RunAsImplAuthenticationProvider provider = new RunAsImplAuthenticationProvider();
        assertTrue(provider.supports(RunAsUserToken.class));
        assertTrue(!provider.supports(TestingAuthenticationToken.class));
    }
}
