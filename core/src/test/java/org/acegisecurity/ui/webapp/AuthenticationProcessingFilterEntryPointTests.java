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

package net.sf.acegisecurity.ui.webapp;

import java.util.HashMap;

import junit.framework.TestCase;

import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;


/**
 * Tests {@link AuthenticationProcessingFilterEntryPoint}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationProcessingFilterEntryPointTests extends TestCase {

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthenticationProcessingFilterEntryPointTests.class);
    }

    public void testDetectsMissingLoginFormUrl() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("loginFormUrl must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");
        assertEquals("/hello", ep.getLoginFormUrl());
    }
    
    public void testSetSslPortMapping() {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        HashMap map = new HashMap();
        try {
            ep.setHttpsPortMapping(map);
        } catch (IllegalArgumentException expected) {
            assertEquals("must map at least one port", expected.getMessage());
        }
        
        map.put(new Integer(0).toString(), new Integer(443).toString());
        try {
            ep.setHttpsPortMapping(map);
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("one or both ports out of legal range"));
        }
        
        map.clear();
        map.put(new Integer(80).toString(), new Integer(100000).toString());
        try {
            ep.setHttpsPortMapping(map);
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("one or both ports out of legal range"));
        }
        
        map.clear();
        map.put(new Integer(80).toString(), new Integer(443).toString());
        ep.setHttpsPortMapping(map);
        map = ep.getTranslatedHttpsPortMapping();
        assertTrue(map.size() == 1);
        assertTrue(((Integer)map.get(new Integer(80))).equals(new Integer(443)));
    }

    public void testNormalOperation() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        ep.setLoginFormUrl("/hello");

        MockHttpServletRequest request = new MockHttpServletRequest(
                "/some_path");
        request.setContextPath("/bigWebApp");

        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();
        ep.commence(request, response);
        assertEquals("/bigWebApp/hello", response.getRedirect());
    }
    
    public void testHttpsOperation() throws Exception {
        AuthenticationProcessingFilterEntryPoint ep = new AuthenticationProcessingFilterEntryPoint();
        
        //TODO: finish later today
    }
    
}
