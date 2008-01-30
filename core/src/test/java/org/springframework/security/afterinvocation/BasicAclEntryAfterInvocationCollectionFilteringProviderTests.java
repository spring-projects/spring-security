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

package org.springframework.security.afterinvocation;

import junit.framework.TestCase;

import org.springframework.security.AuthorizationServiceException;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.MockAclManager;
import org.springframework.security.acl.AclEntry;
import org.springframework.security.acl.AclManager;
import org.springframework.security.acl.basic.MockAclObjectIdentity;
import org.springframework.security.acl.basic.SimpleAclEntry;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.security.util.SimpleMethodInvocation;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link BasicAclEntryAfterInvocationCollectionFilteringProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclEntryAfterInvocationCollectionFilteringProviderTests extends TestCase {
    //~ Constructors ===================================================================================================

    public BasicAclEntryAfterInvocationCollectionFilteringProviderTests() {
        super();
    }

    public BasicAclEntryAfterInvocationCollectionFilteringProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public void testCorrectOperationWhenPrincipalHasIncorrectPermissionToDomainObject()
        throws Exception {
        // Create an AclManager, granting scott only ADMINISTRATION rights
        AclManager aclManager = new MockAclManager("belmont", "scott",
                new AclEntry[] {
                    new SimpleAclEntry("scott", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION)
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create a Collection containing many items
        List list = new Vector();
        list.add("sydney");
        list.add("melbourne");
        list.add("belmont");
        list.add("brisbane");

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("scott", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        List filteredList = (List) provider.decide(auth, new SimpleMethodInvocation(), attr, list);

        assertEquals(0, filteredList.size());
    }

    public void testCorrectOperationWhenPrincipalHasNoPermissionToDomainObject()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "rod",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create a Collection containing many items, which only "belmont"
        // should remain in after filtering by provider
        List list = new Vector();
        list.add("sydney");
        list.add("melbourne");
        list.add("belmont");
        list.add("brisbane");

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("scott", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        List filteredList = (List) provider.decide(auth, new SimpleMethodInvocation(), attr, list);

        assertEquals(0, filteredList.size());
    }

    public void testCorrectOperationWhenPrincipalIsAuthorised()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "rod",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        assertEquals(aclManager, provider.getAclManager());
        provider.afterPropertiesSet();

        // Create a Collection containing many items, which only "belmont"
        // should remain in after filtering by provider
        List list = new Vector();
        list.add("sydney");
        list.add("melbourne");
        list.add("belmont");
        list.add("brisbane");

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("rod", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        List filteredList = (List) provider.decide(auth, new SimpleMethodInvocation(), attr, list);

        assertEquals(1, filteredList.size());
        assertEquals("belmont", filteredList.get(0));
    }

    public void testCorrectOperationWhenReturnedObjectIsArray()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "rod",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        assertEquals(aclManager, provider.getAclManager());
        provider.afterPropertiesSet();

        // Create a Collection containing many items, which only "belmont"
        // should remain in after filtering by provider
        String[] list = new String[4];
        list[0] = "sydney";
        list[1] = "melbourne";
        list[2] = "belmont";
        list[3] = "brisbane";

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("rod", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        String[] filteredList = (String[]) provider.decide(auth, new SimpleMethodInvocation(), attr, list);

        assertEquals(1, filteredList.length);
        assertEquals("belmont", filteredList[0]);
    }

    public void testDetectsIfReturnedObjectIsNotACollection()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "rod",
                new AclEntry[] {
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE),
                    new MockAclEntry()
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("rod", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        try {
            provider.decide(auth, new SimpleMethodInvocation(), attr, new String("RETURN_OBJECT_NOT_COLLECTION"));
            fail("Should have thrown AuthorizationServiceException");
        } catch (AuthorizationServiceException expected) {
            assertTrue(true);
        }
    }

    public void testGrantsAccessIfReturnedObjectIsNull()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "rod",
                new AclEntry[] {
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE),
                    new MockAclEntry()
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("rod", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        List filteredList = (List) provider.decide(auth, new SimpleMethodInvocation(), attr, null);

        assertNull(filteredList);
    }

    public void testRespectsModificationsToProcessConfigAttribute() throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("sydney", "rod",
                new AclEntry[] {
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new MockAclEntry()
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        assertEquals("AFTER_ACL_COLLECTION_READ", provider.getProcessConfigAttribute());
        provider.setProcessConfigAttribute("AFTER_ACL_COLLECTION_ADMIN");
        assertEquals("AFTER_ACL_COLLECTION_ADMIN", provider.getProcessConfigAttribute());
        provider.afterPropertiesSet();

        // Create a Collection containing many items, which only "sydney"
        // should remain in after filtering by provider
        List list = new Vector();
        list.add("sydney");
        list.add("melbourne");
        list.add("belmont");
        list.add("brisbane");

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("rod", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // As no matching config attrib, ensure provider doesn't change list
        assertEquals(4, ((List) provider.decide(auth, new SimpleMethodInvocation(), attr, list)).size());

        // Filter, this time with the conf attrib provider setup to answer
        attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_ADMIN");
        //attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_COLLECTION_ADMIN"));

        List filteredList = (List) provider.decide(auth, new SimpleMethodInvocation(), attr, list);

        assertEquals(1, filteredList.size());
        assertEquals("sydney", filteredList.get(0));
    }

    public void testRespectsModificationsToRequirePermissions()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("sydney", "rod",
                new AclEntry[] {
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new MockAclEntry()
                });

        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        provider.setAclManager(aclManager);
        assertEquals(SimpleAclEntry.READ, provider.getRequirePermission()[0]);
        provider.setRequirePermission(new int[] {SimpleAclEntry.ADMINISTRATION});
        assertEquals(SimpleAclEntry.ADMINISTRATION, provider.getRequirePermission()[0]);
        provider.afterPropertiesSet();

        // Create a Collection containing many items, which only "sydney"
        // should remain in after filtering by provider
        List list = new Vector();
        list.add("sydney");
        list.add("melbourne");
        list.add("belmont");
        list.add("brisbane");

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("rod", "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("AFTER_ACL_COLLECTION_READ");

        // Filter
        List filteredList = (List) provider.decide(auth, new SimpleMethodInvocation(), attr, list);

        assertEquals(1, filteredList.size());
        assertEquals("sydney", filteredList.get(0));
    }

    public void testStartupDetectsMissingAclManager() throws Exception {
        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An aclManager is mandatory", expected.getMessage());
        }
    }

    public void testStartupDetectsMissingProcessConfigAttribute()
        throws Exception {
        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        AclManager aclManager = new MockAclManager("sydney", "rod",
                new AclEntry[] {
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new MockAclEntry()
                });
        provider.setAclManager(aclManager);

        provider.setProcessConfigAttribute(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A processConfigAttribute is mandatory", expected.getMessage());
        }
    }

    public void testStartupDetectsMissingRequirePermission()
        throws Exception {
        BasicAclEntryAfterInvocationCollectionFilteringProvider provider = new BasicAclEntryAfterInvocationCollectionFilteringProvider();
        AclManager aclManager = new MockAclManager("sydney", "rod",
                new AclEntry[] {
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new MockAclEntry()
                });
        provider.setAclManager(aclManager);

        provider.setRequirePermission(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("One or more requirePermission entries is mandatory", expected.getMessage());
        }
    }

    public void testSupportsAnything() {
        assertTrue(new BasicAclEntryAfterInvocationCollectionFilteringProvider().supports(String.class));
    }

    //~ Inner Classes ==================================================================================================

    private class MockAclEntry implements AclEntry {
        // just so AclTag iterates some different types of AclEntrys
    }
}
