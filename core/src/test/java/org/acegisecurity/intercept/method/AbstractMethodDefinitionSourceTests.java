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

package org.acegisecurity.intercept.method;

import junit.framework.TestCase;

import org.acegisecurity.util.SimpleMethodInvocation;

import org.aopalliance.intercept.MethodInvocation;


/**
 * Tests {@link AbstractMethodDefinitionSource} and associated {@link ConfigAttributeDefinition}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractMethodDefinitionSourceTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AbstractMethodDefinitionSourceTests() {
        super();
    }

    public AbstractMethodDefinitionSourceTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractMethodDefinitionSourceTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDoesNotSupportAnotherObject() {
        MockMethodDefinitionSource mds = new MockMethodDefinitionSource(false, true);
        assertFalse(mds.supports(String.class));
    }

    public void testGetAttributesForANonMethodInvocation() {
        MockMethodDefinitionSource mds = new MockMethodDefinitionSource(false, true);

        try {
            mds.getAttributes(new String());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetAttributesForANullObject() {
        MockMethodDefinitionSource mds = new MockMethodDefinitionSource(false, true);

        try {
            mds.getAttributes(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetAttributesForMethodInvocation() {
        MockMethodDefinitionSource mds = new MockMethodDefinitionSource(false, true);

        try {
            mds.getAttributes(new SimpleMethodInvocation());
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }
    }

    public void testSupportsMethodInvocation() {
        MockMethodDefinitionSource mds = new MockMethodDefinitionSource(false, true);
        assertTrue(mds.supports(MethodInvocation.class));
    }
}
