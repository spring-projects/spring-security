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
package org.springframework.security.ui.preauth;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Valery Tydykov
 * 
 */
public class RequestParameterUsernameSourceTest extends TestCase {

    RequestParameterUsernameSource usernameSource;

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        usernameSource = new RequestParameterUsernameSource();
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        usernameSource = null;
    }

    public final void testObtainUsernameSupplied() {
        String key1 = "key1";
        String value1 = "value1";

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(key1, value1);

        usernameSource.setUsernameKey(key1);
        String username = usernameSource.obtainUsername(request);

        assertEquals(value1, username);
    }

    public final void testObtainUsernameNotSupplied() {
        String key1 = "key1";

        MockHttpServletRequest request = new MockHttpServletRequest();

        usernameSource.setUsernameKey(key1);
        String username = usernameSource.obtainUsername(request);

        assertEquals(null, username);
    }
}
