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

package net.sf.acegisecurity.context;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link SecureContextImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecureContextImplTests extends TestCase {
    //~ Constructors ===========================================================

    public SecureContextImplTests() {
        super();
    }

    public SecureContextImplTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SecureContextImplTests.class);
    }

    public void testSecureContextCorrectOperation() {
        SecureContext context = new SecureContextImpl();
        Authentication auth = new UsernamePasswordAuthenticationToken("marissa",
                "koala");
        context.setAuthentication(auth);
        context.validate();
        assertEquals(auth, context.getAuthentication());
        assertTrue(context.toString().lastIndexOf("marissa") != -1);
    }

    public void testSecureContextDetectsMissingAuthenticationObject() {
        SecureContext context = new SecureContextImpl();

        assertTrue(context.toString().lastIndexOf("Null authentication") != -1);

        try {
            context.validate();
            fail("Should have thrown ContextInvalidException");
        } catch (ContextInvalidException expected) {
            assertTrue(true);
        }
    }

    public void testSecureContextDetectsNullAuthenticationObject() {
        SecureContext context = new SecureContextImpl();
        context.setAuthentication(null);

        try {
            context.validate();
            fail("Should have thrown ContextInvalidException");
        } catch (ContextInvalidException expected) {
            assertTrue(true);
        }
    }
}
