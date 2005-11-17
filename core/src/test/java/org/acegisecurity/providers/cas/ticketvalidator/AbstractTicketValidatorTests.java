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

package org.acegisecurity.providers.cas.ticketvalidator;

import junit.framework.TestCase;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.cas.TicketResponse;
import org.acegisecurity.ui.cas.ServiceProperties;

import java.util.Vector;


/**
 * Tests {@link AbstractTicketValidator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractTicketValidatorTests extends TestCase {
    //~ Constructors ===========================================================

    public AbstractTicketValidatorTests() {
        super();
    }

    public AbstractTicketValidatorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractTicketValidatorTests.class);
    }

    public void testDetectsMissingCasValidate() throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setServiceProperties(new ServiceProperties());

        try {
            tv.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A casValidate URL must be set", expected.getMessage());
        }
    }

    public void testDetectsMissingServiceProperties() throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setCasValidate("https://company.com/cas/proxyvalidate");

        try {
            tv.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("serviceProperties must be specified",
                expected.getMessage());
        }
    }

    public void testGetters() throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setCasValidate("https://company.com/cas/proxyvalidate");
        assertEquals("https://company.com/cas/proxyvalidate",
            tv.getCasValidate());

        tv.setServiceProperties(new ServiceProperties());
        assertTrue(tv.getServiceProperties() != null);

        tv.afterPropertiesSet();

        tv.setTrustStore("/some/file/cacerts");
        assertEquals("/some/file/cacerts", tv.getTrustStore());
    }

    public void testSystemPropertySetDuringAfterPropertiesSet()
        throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setCasValidate("https://company.com/cas/proxyvalidate");
        assertEquals("https://company.com/cas/proxyvalidate",
            tv.getCasValidate());

        tv.setServiceProperties(new ServiceProperties());
        assertTrue(tv.getServiceProperties() != null);

        tv.setTrustStore("/some/file/cacerts");
        assertEquals("/some/file/cacerts", tv.getTrustStore());

        String before = System.getProperty("javax.net.ssl.trustStore");
        tv.afterPropertiesSet();
        assertEquals("/some/file/cacerts",
            System.getProperty("javax.net.ssl.trustStore"));

        if (before == null) {
            System.setProperty("javax.net.ssl.trustStore", "");
        } else {
            System.setProperty("javax.net.ssl.trustStore", before);
        }
    }

    //~ Inner Classes ==========================================================

    private class MockAbstractTicketValidator extends AbstractTicketValidator {
        private boolean returnTicket;

        public MockAbstractTicketValidator(boolean returnTicket) {
            this.returnTicket = returnTicket;
        }

        private MockAbstractTicketValidator() {
            super();
        }

        public TicketResponse confirmTicketValid(String serviceTicket)
            throws AuthenticationException {
            if (returnTicket) {
                return new TicketResponse("user", new Vector(),
                    "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            }

            throw new BadCredentialsException("As requested by mock");
        }
    }
}
