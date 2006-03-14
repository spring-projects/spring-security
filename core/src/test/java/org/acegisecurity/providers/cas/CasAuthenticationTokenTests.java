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

package org.acegisecurity.providers.cas;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public CasAuthenticationTokenTests() {
        super();
    }

    public CasAuthenticationTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CasAuthenticationTokenTests.class);
    }

    public void testConstructorRejectsNulls() {
        try {
            new CasAuthenticationToken(null, makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", null, "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), null,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password", null,
                makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), null,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, null, new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(), null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), null, new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testEqualsWhenEqual() {
        List proxyList1 = new Vector();
        proxyList1.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList1,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        List proxyList2 = new Vector();
        proxyList2.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token2 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList2,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        assertEquals(token1, token2);
    }

    public void testGetters() {
        // Build the proxy list returned in the ticket from CAS
        List proxyList = new Vector();
        proxyList.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
        assertEquals("key".hashCode(), token.getKeyHash());
        assertEquals(makeUserDetails(), token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("ROLE_ONE", token.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", token.getAuthorities()[1].getAuthority());
        assertEquals("PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt",
            token.getProxyGrantingTicketIou());
        assertEquals(proxyList, token.getProxyList());
        assertEquals(makeUserDetails().getUsername(),
            token.getUserDetails().getUsername());
    }

    public void testNoArgConstructorDoesntExist() {
        Class clazz = CasAuthenticationToken.class;

        try {
            clazz.getDeclaredConstructor((Class[])null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }

    public void testNotEqualsDueToAbstractParentEqualsCheck() {
        List proxyList1 = new Vector();
        proxyList1.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList1,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        List proxyList2 = new Vector();
        proxyList2.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token2 = new CasAuthenticationToken("key",
        		makeUserDetails("OTHER_NAME"), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList2,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentAuthenticationClass() {
        List proxyList1 = new Vector();
        proxyList1.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList1,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToKey() {
        List proxyList1 = new Vector();
        proxyList1.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList1,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        List proxyList2 = new Vector();
        proxyList2.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token2 = new CasAuthenticationToken("DIFFERENT_KEY",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList2,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToProxyGrantingTicket() {
        List proxyList1 = new Vector();
        proxyList1.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList1,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        List proxyList2 = new Vector();
        proxyList2.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token2 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList2,
                "PGTIOU-SOME_OTHER_VALUE");

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToProxyList() {
        List proxyList1 = new Vector();
        proxyList1.add("https://localhost/newPortal/j_acegi_cas_security_check");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList1,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        List proxyList2 = new Vector();
        proxyList2.add(
            "https://localhost/SOME_OTHER_PORTAL/j_acegi_cas_security_check");

        CasAuthenticationToken token2 = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), proxyList2,
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");

        assertTrue(!token1.equals(token2));
    }

    public void testSetAuthenticated() {
        CasAuthenticationToken token = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());
    }

    public void testToString() {
        CasAuthenticationToken token = new CasAuthenticationToken("key",
        		makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, makeUserDetails(), new Vector(),
                "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
        String result = token.toString();
        assertTrue(result.lastIndexOf("Proxy List:") != -1);
        assertTrue(result.lastIndexOf("Proxy-Granting Ticket IOU:") != -1);
        assertTrue(result.lastIndexOf("Credentials (Service/Proxy Ticket):") != -1);
    }

    private UserDetails makeUserDetails() {
    	return makeUserDetails("user");
    }
    
    private UserDetails makeUserDetails(final String name) {
        return new User(name, "password", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
    }
}
