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

package net.sf.acegisecurity.providers.cas;

import junit.framework.TestCase;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link TicketResponse}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TicketResponseTests extends TestCase {
    //~ Constructors ===========================================================

    public TicketResponseTests() {
        super();
    }

    public TicketResponseTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(TicketResponseTests.class);
    }

    public void testConstructorAcceptsNullProxyGrantingTicketIOU() {
        TicketResponse ticket = new TicketResponse("marissa", new Vector(), null);
        assertEquals("", ticket.getProxyGrantingTicketIou());
    }

    public void testConstructorAcceptsNullProxyList() {
        TicketResponse ticket = new TicketResponse("marissa", null,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
        assertEquals(new Vector(), ticket.getProxyList());
    }

    public void testConstructorRejectsNullUser() {
        try {
            new TicketResponse(null, new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetters() {
        // Build the proxy list returned in the ticket from CAS
        List proxyList = new Vector();
        proxyList.add("https://localhost/newPortal/j_acegi_cas_security_check");

        TicketResponse ticket = new TicketResponse("marissa", proxyList,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
        assertEquals("marissa", ticket.getUser());
        assertEquals(proxyList, ticket.getProxyList());
        assertEquals("PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt",
            ticket.getProxyGrantingTicketIou());
    }

    public void testNoArgConstructor() {
        try {
            new TicketResponse();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testToString() {
        TicketResponse ticket = new TicketResponse("marissa", null,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
        String result = ticket.toString();
        assertTrue(result.lastIndexOf("Proxy List:") != -1);
        assertTrue(result.lastIndexOf("Proxy-Granting Ticket IOU:") != -1);
        assertTrue(result.lastIndexOf("User:") != -1);
    }
}
