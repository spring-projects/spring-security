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

package org.acegisecurity.afterinvocation;

import junit.framework.TestCase;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.MockAclManager;
import org.acegisecurity.SecurityConfig;
import org.acegisecurity.acl.AclEntry;
import org.acegisecurity.acl.AclManager;
import org.acegisecurity.acl.basic.MockAclObjectIdentity;
import org.acegisecurity.acl.basic.SimpleAclEntry;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.util.SimpleMethodInvocation;
import org.springframework.context.support.StaticMessageSource;


/**
 * Tests {@link BasicAclEntryAfterInvocationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclEntryAfterInvocationProviderTests extends TestCase {
    //~ Constructors ===========================================================

    public BasicAclEntryAfterInvocationProviderTests() {
        super();
    }

    public BasicAclEntryAfterInvocationProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BasicAclEntryAfterInvocationProviderTests.class);
    }

    public void testCorrectOperationWhenPrincipalHasIncorrectPermissionToDomainObject()
        throws Exception {
        // Create an AclManager, granting scott only ADMINISTRATION rights
        AclManager aclManager = new MockAclManager("belmont", "scott",
                new AclEntry[] {new SimpleAclEntry("scott",
                        new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION)});

        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("scott",
                "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_READ"));

        try {
            provider.decide(auth, new SimpleMethodInvocation(), attr, "belmont");
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
    }

    public void testCorrectOperationWhenPrincipalHasNoPermissionToDomainObject()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "marissa",
                new AclEntry[] {new MockAclEntry(), new SimpleAclEntry(
                        "marissa", new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION), new SimpleAclEntry(
                        "marissa", new MockAclObjectIdentity(), null,
                        SimpleAclEntry.READ), new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)});

        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("scott",
                "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_READ"));

        try {
            provider.decide(auth, new SimpleMethodInvocation(), attr, "belmont");
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
    }

    public void testCorrectOperationWhenPrincipalIsAuthorised()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "marissa",
                new AclEntry[] {new MockAclEntry(), new SimpleAclEntry(
                        "marissa", new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION), new SimpleAclEntry(
                        "marissa", new MockAclObjectIdentity(), null,
                        SimpleAclEntry.READ), new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)});

        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        provider.setAclManager(aclManager);
        assertEquals(aclManager, provider.getAclManager());
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("marissa",
                "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_READ"));

        // Filter
        assertEquals("belmont",
            provider.decide(auth, new SimpleMethodInvocation(), attr, "belmont"));
    }

    public void testGrantsAccessIfReturnedObjectIsNull()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("belmont", "marissa",
                new AclEntry[] {new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION), new SimpleAclEntry(
                        "marissa", new MockAclObjectIdentity(), null,
                        SimpleAclEntry.READ), new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE), new MockAclEntry()});

        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        provider.setAclManager(aclManager);
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("marissa",
                "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_READ"));

        // Filter
        assertNull(provider.decide(auth, new SimpleMethodInvocation(), attr, null));
    }

    public void testRespectsModificationsToProcessConfigAttribute()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("sydney", "marissa",
                new AclEntry[] {new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null, SimpleAclEntry.READ), new MockAclEntry()});

        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        provider.setAclManager(aclManager);
        assertEquals("AFTER_ACL_READ", provider.getProcessConfigAttribute());
        provider.setProcessConfigAttribute("AFTER_ACL_ADMIN");
        assertEquals("AFTER_ACL_ADMIN", provider.getProcessConfigAttribute());
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("marissa",
                "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_READ"));

        // As no matching config attrib, ensure provider returns original obj
        assertEquals("sydney",
            provider.decide(auth, new SimpleMethodInvocation(), attr, "sydney"));

        // Filter, this time with the conf attrib provider setup to answer
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_ADMIN"));
        assertEquals("sydney",
            provider.decide(auth, new SimpleMethodInvocation(), attr, "sydney"));
    }

    public void testRespectsModificationsToRequirePermissions()
        throws Exception {
        // Create an AclManager
        AclManager aclManager = new MockAclManager("sydney", "marissa",
                new AclEntry[] {new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION), new MockAclEntry()});

        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        provider.setAclManager(aclManager);
        assertEquals(SimpleAclEntry.READ, provider.getRequirePermission()[0]);
        provider.setRequirePermission(new int[] {SimpleAclEntry.ADMINISTRATION});
        assertEquals(SimpleAclEntry.ADMINISTRATION,
            provider.getRequirePermission()[0]);
        provider.afterPropertiesSet();

        // Create the Authentication and Config Attribs we'll be presenting
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("marissa",
                "NOT_USED");
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition();
        attr.addConfigAttribute(new SecurityConfig("AFTER_ACL_READ"));

        // Filter
        assertEquals("sydney",
            provider.decide(auth, new SimpleMethodInvocation(), attr, "sydney"));
    }

    public void testStartupDetectsMissingAclManager() throws Exception {
        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An aclManager is mandatory", expected.getMessage());
        }
    }

    public void testStartupDetectsMissingProcessConfigAttribute()
        throws Exception {
        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        AclManager aclManager = new MockAclManager("sydney", "marissa",
                new AclEntry[] {new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION), new MockAclEntry()});
        provider.setAclManager(aclManager);

        provider.setProcessConfigAttribute(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A processConfigAttribute is mandatory",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingRequirePermission()
        throws Exception {
        BasicAclEntryAfterInvocationProvider provider = new BasicAclEntryAfterInvocationProvider();
        provider.setMessageSource(new StaticMessageSource());
        AclManager aclManager = new MockAclManager("sydney", "marissa",
                new AclEntry[] {new SimpleAclEntry("marissa",
                        new MockAclObjectIdentity(), null,
                        SimpleAclEntry.ADMINISTRATION), new MockAclEntry()});
        provider.setAclManager(aclManager);

        provider.setRequirePermission(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("One or more requirePermission entries is mandatory",
                expected.getMessage());
        }
    }

    public void testSupportsAnything() {
        assertTrue(new BasicAclEntryAfterInvocationProvider().supports(
                String.class));
    }

    //~ Inner Classes ==========================================================

    private class MockAclEntry implements AclEntry {
        // just so AclTag iterates some different types of AclEntrys
    }
}
