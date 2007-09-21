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

package org.springframework.security.providers.cas.ticketvalidator;

import junit.framework.TestCase;

import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;

import org.springframework.security.providers.cas.TicketResponse;

import org.springframework.security.ui.cas.ServiceProperties;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ClassPathResource;

import java.util.Vector;


/**
 * Tests {@link AbstractTicketValidator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractTicketValidatorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AbstractTicketValidatorTests() {
    }

    public AbstractTicketValidatorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

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
            assertEquals("serviceProperties must be specified", expected.getMessage());
        }
    }

    public void testGetters() throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setCasValidate("https://company.com/cas/proxyvalidate");
        assertEquals("https://company.com/cas/proxyvalidate", tv.getCasValidate());

        tv.setServiceProperties(new ServiceProperties());
        assertTrue(tv.getServiceProperties() != null);

        tv.afterPropertiesSet();

        tv.setTrustStore("/some/file/cacerts");
        assertEquals("/some/file/cacerts", tv.getTrustStore());
    }

    public void testTrustStoreSystemPropertySetDuringAfterPropertiesSet() throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setCasValidate("https://company.com/cas/proxyvalidate");
        tv.setServiceProperties(new ServiceProperties());

        // We need an existing file to use as the truststore property
        Resource r = new ClassPathResource("log4j.properties");
        String filename = r.getFile().getAbsolutePath();

        tv.setTrustStore(filename);
        assertEquals(filename, tv.getTrustStore());

        String before = System.getProperty("javax.net.ssl.trustStore");
        tv.afterPropertiesSet();
        assertEquals(filename, System.getProperty("javax.net.ssl.trustStore"));

        if (before == null) {
            System.setProperty("javax.net.ssl.trustStore", "");
        } else {
            System.setProperty("javax.net.ssl.trustStore", before);
        }
    }

    public void testMissingTrustStoreFileCausesException() throws Exception {
        AbstractTicketValidator tv = new MockAbstractTicketValidator();
        tv.setServiceProperties(new ServiceProperties());
        tv.setCasValidate("https://company.com/cas/proxyvalidate");
        tv.setTrustStore("/non/existent/file");

        try {
            tv.afterPropertiesSet();

            fail("Expected exception with non-existent truststore");
        } catch (IllegalArgumentException expected) {
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockAbstractTicketValidator extends AbstractTicketValidator {
        private boolean returnTicket;

        public MockAbstractTicketValidator(boolean returnTicket) {
            this.returnTicket = returnTicket;
        }

        private MockAbstractTicketValidator() {
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
