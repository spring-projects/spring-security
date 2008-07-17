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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests extends TestCase {

    public AllTests(String s) {
        super(s);
    }

    public static Test suite() {
        TestSuite suite = new TestSuite();
        suite
            .addTestSuite(org.springframework.security.ui.preauth.AttributesSourceWebAuthenticationDetailsSourceTest.class);
        suite
            .addTestSuite(org.springframework.security.ui.preauth.CookieAttributesSourceTest.class);
        suite.addTestSuite(org.springframework.security.ui.preauth.CookieUsernameSourceTest.class);
        suite
            .addTestSuite(org.springframework.security.ui.preauth.HeaderAttributesSourceTest.class);
        suite.addTestSuite(org.springframework.security.ui.preauth.HeaderUsernameSourceTest.class);
        suite
            .addTestSuite(org.springframework.security.ui.preauth.PropertyAttributesSourceTest.class);
        suite
            .addTestSuite(org.springframework.security.ui.preauth.RemoteUserUsernameSourceTest.class);
        suite
            .addTestSuite(org.springframework.security.ui.preauth.RequestParameterUsernameSourceTest.class);
        suite
            .addTestSuite(org.springframework.security.ui.preauth.UsernameSourcePreAuthenticatedProcessingFilterTest.class);
        return suite;
    }
}
