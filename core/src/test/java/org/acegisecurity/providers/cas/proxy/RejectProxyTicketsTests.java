/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.cas.proxy;

import junit.framework.TestCase;

import net.sf.acegisecurity.providers.cas.ProxyUntrustedException;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link RejectProxyTickets}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RejectProxyTicketsTests extends TestCase {
    //~ Constructors ===========================================================

    public RejectProxyTicketsTests() {
        super();
    }

    public RejectProxyTicketsTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RejectProxyTicketsTests.class);
    }

    public void testAcceptsIfNoProxiesInTicket() {
        RejectProxyTickets proxyDecider = new RejectProxyTickets();
        List proxyList = new Vector(); // no proxies in list

        proxyDecider.confirmProxyListTrusted(proxyList);
        assertTrue(true);
    }

    public void testDoesNotAcceptNull() {
        RejectProxyTickets proxyDecider = new RejectProxyTickets();

        try {
            proxyDecider.confirmProxyListTrusted(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("proxyList cannot be null", expected.getMessage());
        }
    }

    public void testRejectsIfAnyProxyInList() {
        RejectProxyTickets proxyDecider = new RejectProxyTickets();
        List proxyList = new Vector();
        proxyList.add("https://localhost/webApp/j_acegi_cas_security_check");

        try {
            proxyDecider.confirmProxyListTrusted(proxyList);
            fail("Should have thrown ProxyUntrustedException");
        } catch (ProxyUntrustedException expected) {
            assertTrue(true);
        }
    }
}
