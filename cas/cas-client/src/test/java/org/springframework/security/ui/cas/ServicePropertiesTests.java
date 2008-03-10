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

package org.springframework.security.ui.cas;

import junit.framework.TestCase;


/**
 * Tests {@link ServiceProperties}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ServicePropertiesTests extends TestCase {
    //~ Constructors ===================================================================================================

    public ServicePropertiesTests() {
        super();
    }

    public ServicePropertiesTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ServicePropertiesTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsMissingLoginFormUrl() throws Exception {
        ServiceProperties sp = new ServiceProperties();

        try {
            sp.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("service must be specified.", expected.getMessage());
        }
    }

    public void testGettersSetters() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.setSendRenew(false);
        assertFalse(sp.isSendRenew());
        sp.setSendRenew(true);
        assertTrue(sp.isSendRenew());

        sp.setService("https://mycompany.com/service");
        assertEquals("https://mycompany.com/service", sp.getService());

        sp.afterPropertiesSet();
    }
}
