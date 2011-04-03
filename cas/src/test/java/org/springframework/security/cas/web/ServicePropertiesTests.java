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

package org.springframework.security.cas.web;

import static junit.framework.Assert.*;

import org.junit.Test;
import org.springframework.security.cas.SamlServiceProperties;
import org.springframework.security.cas.ServiceProperties;

/**
 * Tests {@link ServiceProperties}.
 *
 * @author Ben Alex
 */
public class ServicePropertiesTests {
    //~ Methods ========================================================================================================

    @Test(expected=IllegalArgumentException.class)
    public void detectsMissingService() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.afterPropertiesSet();
    }

    @Test
    public void allowNullServiceWhenAuthenticateAllTokens() throws Exception {
        ServiceProperties sp = new ServiceProperties();
        sp.setAuthenticateAllArtifacts(true);
        sp.afterPropertiesSet();
        sp.setAuthenticateAllArtifacts(false);
        try {
            sp.afterPropertiesSet();
            fail("Expected Exception");
        }catch(IllegalArgumentException success) {}
    }

    @Test
    public void testGettersSetters() throws Exception {
        ServiceProperties[] sps = {new ServiceProperties(), new SamlServiceProperties()};
        for(ServiceProperties sp : sps) {
            sp.setSendRenew(false);
            assertFalse(sp.isSendRenew());
            sp.setSendRenew(true);
            assertTrue(sp.isSendRenew());
            sp.setArtifactParameter("notticket");
            assertEquals("notticket", sp.getArtifactParameter());
            sp.setServiceParameter("notservice");
            assertEquals("notservice", sp.getServiceParameter());

            sp.setService("https://mycompany.com/service");
            assertEquals("https://mycompany.com/service", sp.getService());

            sp.afterPropertiesSet();
        }
    }
}
