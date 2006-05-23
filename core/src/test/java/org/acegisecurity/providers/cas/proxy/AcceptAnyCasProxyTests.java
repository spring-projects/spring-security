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

package org.acegisecurity.providers.cas.proxy;

import junit.framework.TestCase;

import java.util.Vector;


/**
 * Tests {@link AcceptAnyCasProxy}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AcceptAnyCasProxyTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AcceptAnyCasProxyTests() {
        super();
    }

    public AcceptAnyCasProxyTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AcceptAnyCasProxyTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDoesNotAcceptNull() {
        AcceptAnyCasProxy proxyDecider = new AcceptAnyCasProxy();

        try {
            proxyDecider.confirmProxyListTrusted(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("proxyList cannot be null", expected.getMessage());
        }
    }

    public void testNormalOperation() {
        AcceptAnyCasProxy proxyDecider = new AcceptAnyCasProxy();
        proxyDecider.confirmProxyListTrusted(new Vector());
        assertTrue(true); // as no Exception thrown
    }
}
