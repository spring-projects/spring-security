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
 * Tests {@link SimpleAclEntry}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SimpleAclEntryTests extends TestCase {
    //~ Constructors ===================================================================================================

    public SimpleAclEntryTests() {
        super();
    }

    public SimpleAclEntryTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SimpleAclEntryTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testCorrectOperation() {
        String recipient = "marissa";
        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "12");
        SimpleAclEntry acl = new SimpleAclEntry(recipient, objectIdentity, null, 0);

        assertFalse(acl.isPermitted(SimpleAclEntry.ADMINISTRATION));
        acl.addPermission(SimpleAclEntry.ADMINISTRATION);
        assertTrue(acl.isPermitted(SimpleAclEntry.ADMINISTRATION));
        assertFalse(acl.isPermitted(SimpleAclEntry.CREATE));
        assertFalse(acl.isPermitted(SimpleAclEntry.DELETE));
        assertFalse(acl.isPermitted(SimpleAclEntry.READ));
        assertFalse(acl.isPermitted(SimpleAclEntry.WRITE));
        assertEquals("A----", acl.printPermissionsBlock());
        acl.deletePermission(SimpleAclEntry.ADMINISTRATION);
        assertFalse(acl.isPermitted(SimpleAclEntry.ADMINISTRATION));
        assertEquals("-----", acl.printPermissionsBlock());

        acl.addPermissions(new int[] {SimpleAclEntry.READ, SimpleAclEntry.WRITE});
        acl.addPermission(SimpleAclEntry.CREATE);
        assertFalse(acl.isPermitted(SimpleAclEntry.ADMINISTRATION));
        assertTrue(acl.isPermitted(SimpleAclEntry.CREATE));
        assertFalse(acl.isPermitted(SimpleAclEntry.DELETE));
        assertTrue(acl.isPermitted(SimpleAclEntry.READ));
        assertTrue(acl.isPermitted(SimpleAclEntry.WRITE));
        assertEquals("-RWC-", acl.printPermissionsBlock());

        acl.deletePermission(SimpleAclEntry.CREATE);
        acl.deletePermissions(new int[] {SimpleAclEntry.READ, SimpleAclEntry.WRITE});
        assertEquals("-----", acl.printPermissionsBlock());

        acl.togglePermission(SimpleAclEntry.CREATE);
        assertTrue(acl.isPermitted(SimpleAclEntry.CREATE));
        assertFalse(acl.isPermitted(SimpleAclEntry.ADMINISTRATION));
        acl.togglePermission(SimpleAclEntry.CREATE);
        assertFalse(acl.isPermitted(SimpleAclEntry.CREATE));

        acl.togglePermission(SimpleAclEntry.DELETE);
        assertTrue(acl.isPermitted(SimpleAclEntry.DELETE));
        assertEquals("----D", acl.printPermissionsBlock());
    }

    public void testDetectsNullOnMainConstructor() {
        String recipient = "marissa";
        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "12");

        try {
            new SimpleAclEntry(recipient, null, null, 2);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new SimpleAclEntry(null, objectIdentity, null, 2);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        SimpleAclEntry acl = new SimpleAclEntry();

        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "693");
        acl.setAclObjectIdentity(objectIdentity);
        assertEquals(objectIdentity, acl.getAclObjectIdentity());

        AclObjectIdentity parentObjectIdentity = new NamedEntityObjectIdentity("domain", "13");
        acl.setAclObjectParentIdentity(parentObjectIdentity);
        assertEquals(parentObjectIdentity, acl.getAclObjectParentIdentity());

        acl.setMask(2);
        assertEquals(2, acl.getMask());

        acl.setRecipient("scott");
        assertEquals("scott", acl.getRecipient());
    }

    public void testRejectsInvalidMasksInAddMethod() {
        String recipient = "marissa";
        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "12");
        SimpleAclEntry acl = new SimpleAclEntry(recipient, objectIdentity, null, 4);

        try {
            acl.addPermission(Integer.MAX_VALUE);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsInvalidMasksInDeleteMethod() {
        String recipient = "marissa";
        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "12");
        SimpleAclEntry acl = new SimpleAclEntry(recipient, objectIdentity, null, 0);
        acl.addPermissions(new int[] {SimpleAclEntry.READ, SimpleAclEntry.WRITE, SimpleAclEntry.CREATE});

        try {
            acl.deletePermission(SimpleAclEntry.READ); // can't write if we can't read
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsInvalidMasksInTogglePermissionMethod() {
        String recipient = "marissa";
        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "12");
        SimpleAclEntry acl = new SimpleAclEntry(recipient, objectIdentity, null, 0);
        acl.addPermissions(new int[] {SimpleAclEntry.READ, SimpleAclEntry.WRITE, SimpleAclEntry.CREATE});

        try {
            acl.togglePermission(SimpleAclEntry.READ); // can't write if we can't read
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testToString() {
        String recipient = "marissa";
        AclObjectIdentity objectIdentity = new NamedEntityObjectIdentity("domain", "12");
        SimpleAclEntry acl = new SimpleAclEntry(recipient, objectIdentity, null, 0);
        acl.addPermissions(new int[] {SimpleAclEntry.READ, SimpleAclEntry.WRITE, SimpleAclEntry.CREATE});
        assertTrue(acl.toString().endsWith("marissa=-RWC- ............................111. (14)]"));
    }

    public void testParsePermission() {
        assertPermission("NOTHING", 0);
        assertPermission("ADMINISTRATION", 1);
        assertPermission("READ", 2);
        assertPermission("WRITE", 4);
        assertPermission("CREATE", 8);
        assertPermission("DELETE", 16);
        assertPermission("READ_WRITE_DELETE", 22);
    }

    public void testParsePermissionWrongValues() {
        try {
            SimpleAclEntry.parsePermission("X");
            fail(IllegalArgumentException.class.getName() + " must have been thrown.");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    private void assertPermission(String permission, int value) {
        assertEquals(value, SimpleAclEntry.parsePermission(permission));
    }
}
