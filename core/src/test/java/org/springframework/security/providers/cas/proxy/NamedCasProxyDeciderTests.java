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

package org.springframework.security.providers.cas.proxy;

import junit.framework.TestCase;

import org.springframework.security.providers.cas.ProxyUntrustedException;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link NamedCasProxyDecider}.
 */
public class NamedCasProxyDeciderTests extends TestCase {
    //~ Constructors ===================================================================================================

    public NamedCasProxyDeciderTests() {
        super();
    }

    public NamedCasProxyDeciderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(NamedCasProxyDeciderTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAcceptsIfNearestProxyIsAuthorized()
        throws Exception {
        NamedCasProxyDecider proxyDecider = new NamedCasProxyDecider();

        // Build the ticket returned from CAS
        List proxyList = new Vector();
        proxyList.add("https://localhost/newPortal/j_acegi_cas_security_check");

        // Build the list of valid nearest proxies
        List validProxies = new Vector();
        validProxies.add("https://localhost/portal/j_acegi_cas_security_check");
        validProxies.add("https://localhost/newPortal/j_acegi_cas_security_check");
        proxyDecider.setValidProxies(validProxies);
        proxyDecider.afterPropertiesSet();

        proxyDecider.confirmProxyListTrusted(proxyList);
        assertTrue(true);
    }

    public void testAcceptsIfNoProxiesInTicket() {
        NamedCasProxyDecider proxyDecider = new NamedCasProxyDecider();

        List proxyList = new Vector(); // no proxies in list

        proxyDecider.confirmProxyListTrusted(proxyList);
        assertTrue(true);
    }

    public void testDetectsMissingValidProxiesList() throws Exception {
        NamedCasProxyDecider proxyDecider = new NamedCasProxyDecider();

        try {
            proxyDecider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A validProxies list must be set", expected.getMessage());
        }
    }

    public void testDoesNotAcceptNull() {
        NamedCasProxyDecider proxyDecider = new NamedCasProxyDecider();

        try {
            proxyDecider.confirmProxyListTrusted(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("proxyList cannot be null", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        NamedCasProxyDecider proxyDecider = new NamedCasProxyDecider();

        // Build the list of valid nearest proxies
        List validProxies = new Vector();
        validProxies.add("https://localhost/portal/j_acegi_cas_security_check");
        validProxies.add("https://localhost/newPortal/j_acegi_cas_security_check");
        proxyDecider.setValidProxies(validProxies);

        assertEquals(validProxies, proxyDecider.getValidProxies());
    }

    public void testRejectsIfNearestProxyIsNotAuthorized()
        throws Exception {
        NamedCasProxyDecider proxyDecider = new NamedCasProxyDecider();

        // Build the ticket returned from CAS
        List proxyList = new Vector();
        proxyList.add("https://localhost/untrustedWebApp/j_acegi_cas_security_check");

        // Build the list of valid nearest proxies
        List validProxies = new Vector();
        validProxies.add("https://localhost/portal/j_acegi_cas_security_check");
        validProxies.add("https://localhost/newPortal/j_acegi_cas_security_check");
        proxyDecider.setValidProxies(validProxies);
        proxyDecider.afterPropertiesSet();

        try {
            proxyDecider.confirmProxyListTrusted(proxyList);
            fail("Should have thrown ProxyUntrustedException");
        } catch (ProxyUntrustedException expected) {
            assertTrue(true);
        }
    }
}
