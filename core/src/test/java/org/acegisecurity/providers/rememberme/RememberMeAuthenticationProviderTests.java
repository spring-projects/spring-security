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

package org.acegisecurity.providers.rememberme;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.TestingAuthenticationToken;


/**
 * Tests {@link RememberMeAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeAuthenticationProviderTests extends TestCase {
    //~ Constructors ===========================================================

    public RememberMeAuthenticationProviderTests() {
        super();
    }

    public RememberMeAuthenticationProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RememberMeAuthenticationProviderTests.class);
    }

    public void testDetectsAnInvalidKey() throws Exception {
        RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider();
        aap.setKey("qwerty");

        RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("WRONG_KEY",
                "Test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        try {
            Authentication result = aap.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertEquals("The presented RememberMeAuthenticationToken does not contain the expected key",
                expected.getMessage());
        }
    }

    public void testDetectsMissingKey() throws Exception {
        RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider();

        try {
            aap.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() throws Exception {
        RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider();
        aap.setKey("qwerty");
        aap.afterPropertiesSet();
        assertEquals("qwerty", aap.getKey());
    }

    public void testIgnoresClassesItDoesNotSupport() throws Exception {
        RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider();
        aap.setKey("qwerty");

        TestingAuthenticationToken token = new TestingAuthenticationToken("user",
                "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        assertFalse(aap.supports(TestingAuthenticationToken.class));

        // Try it anyway
        assertNull(aap.authenticate(token));
    }

    public void testNormalOperation() throws Exception {
        RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider();
        aap.setKey("qwerty");

        RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("qwerty",
                "Test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        Authentication result = aap.authenticate(token);

        assertEquals(result, token);
    }

    public void testSupports() {
        RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider();
        assertTrue(aap.supports(RememberMeAuthenticationToken.class));
        assertFalse(aap.supports(TestingAuthenticationToken.class));
    }
}
