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

package org.acegisecurity.acl.basic;

import junit.framework.TestCase;


/**
 * Tests {@link NamedEntityObjectIdentity}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NamedEntityObjectIdentityTests extends TestCase {
    //~ Constructors ===================================================================================================

    public NamedEntityObjectIdentityTests() {
        super();
    }

    public NamedEntityObjectIdentityTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(NamedEntityObjectIdentityTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testConstructionViaReflection() throws Exception {
        SomeDomain domainObject = new SomeDomain();
        domainObject.setId(34);

        NamedEntityObjectIdentity name = new NamedEntityObjectIdentity(domainObject);
        assertEquals("34", name.getId());
        assertEquals(domainObject.getClass().getName(), name.getClassname());
        name.toString();
    }

    public void testConstructionViaReflectionFailsIfNoGetIdMethod()
        throws Exception {
        try {
            new NamedEntityObjectIdentity(new Integer(45));
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testConstructionViaReflectionFailsIfNullPassed()
        throws Exception {
        try {
            new NamedEntityObjectIdentity(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testEquality() {
        NamedEntityObjectIdentity original = new NamedEntityObjectIdentity("foo", "12");
        assertFalse(original.equals(null));
        assertFalse(original.equals(new Integer(354)));
        assertFalse(original.equals(new NamedEntityObjectIdentity("foo", "23232")));
        assertTrue(original.equals(new NamedEntityObjectIdentity("foo", "12")));
        assertTrue(original.equals(original));
    }

    public void testNoArgConstructorDoesntExist() {
        Class clazz = NamedEntityObjectIdentity.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }

    public void testNormalConstructionRejectedIfInvalidArguments()
        throws Exception {
        try {
            new NamedEntityObjectIdentity(null, "12");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new NamedEntityObjectIdentity("classname", null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new NamedEntityObjectIdentity("", "12");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new NamedEntityObjectIdentity("classname", "");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testNormalOperation() {
        NamedEntityObjectIdentity name = new NamedEntityObjectIdentity("domain", "id");
        assertEquals("domain", name.getClassname());
        assertEquals("id", name.getId());
    }
}
