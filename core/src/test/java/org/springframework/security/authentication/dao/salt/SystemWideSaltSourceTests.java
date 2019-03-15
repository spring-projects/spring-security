/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.dao.salt;

import org.springframework.security.authentication.dao.SystemWideSaltSource;

import junit.framework.TestCase;


/**
 * Tests {@link SystemWideSaltSource}.
 *
 * @author Ben Alex
 */
public class SystemWideSaltSourceTests extends TestCase {
    //~ Constructors ===================================================================================================

    public SystemWideSaltSourceTests() {
        super();
    }

    public SystemWideSaltSourceTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SystemWideSaltSourceTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsMissingSystemWideSalt() throws Exception {
        SystemWideSaltSource saltSource = new SystemWideSaltSource();

        try {
            saltSource.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A systemWideSalt must be set", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        SystemWideSaltSource saltSource = new SystemWideSaltSource();
        saltSource.setSystemWideSalt("helloWorld");
        assertEquals("helloWorld", saltSource.getSystemWideSalt());
    }

    public void testNormalOperation() throws Exception {
        SystemWideSaltSource saltSource = new SystemWideSaltSource();
        saltSource.setSystemWideSalt("helloWorld");
        saltSource.afterPropertiesSet();
        assertEquals("helloWorld", saltSource.getSalt(null));
    }
}
