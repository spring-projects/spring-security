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

package org.acegisecurity.runas;

import junit.framework.TestCase;

import org.acegisecurity.SecurityConfig;


/**
 * Tests {@link NullRunAsManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NullRunAsManagerTests extends TestCase {
    //~ Constructors ===========================================================

    public NullRunAsManagerTests() {
        super();
    }

    public NullRunAsManagerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(NullRunAsManagerTests.class);
    }

    public void testAlwaysReturnsNull() {
        NullRunAsManager runAs = new NullRunAsManager();
        assertNull(runAs.buildRunAs(null, null, null));
    }

    public void testAlwaysSupportsClass() {
        NullRunAsManager runAs = new NullRunAsManager();
        assertTrue(runAs.supports(String.class));
    }

    public void testNeverSupportsAttribute() {
        NullRunAsManager runAs = new NullRunAsManager();
        assertFalse(runAs.supports(new SecurityConfig("X")));
    }
}
