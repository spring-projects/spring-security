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

package org.springframework.security.vote;

import junit.framework.TestCase;

import org.springframework.security.AuthorizationServiceException;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.MockAclManager;
import org.springframework.security.SecurityConfig;
import org.springframework.security.acl.AclEntry;
import org.springframework.security.acl.AclManager;
import org.springframework.security.acl.basic.MockAclObjectIdentity;
import org.springframework.security.acl.basic.SimpleAclEntry;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;
import org.aopalliance.intercept.MethodInvocation;
import org.aspectj.lang.JoinPoint;

import java.lang.reflect.Method;

/**
 * Tests {@link BasicAclEntryVoter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAclEntryVoterTests extends TestCase {
    //~ Constructors ===================================================================================================

    public BasicAclEntryVoterTests() {
        super();
    }

    public BasicAclEntryVoterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private MethodInvocation getMethodInvocation(SomeDomainObject domainObject)
        throws Exception {
        Class clazz = SomeDomainObjectManager.class;
        Method method = clazz.getMethod("someServiceMethod", new Class[] {SomeDomainObject.class});

        return new SimpleMethodInvocation(method, new Object[] {domainObject});
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BasicAclEntryVoterTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testNormalOperation() throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject, "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        assertEquals(aclManager, voter.getAclManager());
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        assertEquals("FOO_ADMIN_OR_WRITE_ACCESS", voter.getProcessConfigAttribute());
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        assertEquals(2, voter.getRequirePermission().length);
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        assertEquals(SomeDomainObject.class, voter.getProcessDomainObjectClass());
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        MethodInvocation mi = getMethodInvocation(domainObject);

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr));
    }

    public void testOnlySupportsMethodInvocationAndJoinPoint() {
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        assertTrue(voter.supports(MethodInvocation.class));
        assertTrue(voter.supports(JoinPoint.class));
        assertFalse(voter.supports(String.class));
    }

    public void testStartupRejectsMissingAclManager() throws Exception {
        AclManager aclManager = new MockAclManager("domain1", "rod",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[] {SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);

        try {
            voter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupRejectsMissingProcessConfigAttribute()
        throws Exception {
        AclManager aclManager = new MockAclManager("domain1", "rod",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setRequirePermission(new int[] {SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);

        try {
            voter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupRejectsMissingProcessDomainObjectClass()
        throws Exception {
        BasicAclEntryVoter voter = new BasicAclEntryVoter();

        try {
            voter.setProcessDomainObjectClass(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupRejectsMissingRequirePermission()
        throws Exception {
        AclManager aclManager = new MockAclManager("domain1", "rod",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setProcessDomainObjectClass(SomeDomainObject.class);

        try {
            voter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSupportsConfigAttribute() {
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setProcessConfigAttribute("foobar");
        assertTrue(voter.supports(new SecurityConfig("foobar")));
    }

    public void testVoterAbstainsIfDomainObjectIsNull()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject, "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("A_DIFFERENT_ATTRIBUTE");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        MethodInvocation mi = getMethodInvocation(domainObject);

        assertEquals(AccessDecisionVoter.ACCESS_ABSTAIN,
                voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr));
    }

    public void testVoterAbstainsIfNotMatchingConfigAttribute()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = null;

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject, "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        MethodInvocation mi = getMethodInvocation(domainObject);

        assertEquals(AccessDecisionVoter.ACCESS_ABSTAIN,
                voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr));
    }

    public void testVoterCanDenyAccessBasedOnInternalMethodOfDomainObject()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject.getParent(), "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.setInternalMethod("getParent");
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        MethodInvocation mi = getMethodInvocation(domainObject);

        assertEquals(AccessDecisionVoter.ACCESS_DENIED,
                voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr));
    }

    public void testVoterCanDenyAccessIfPrincipalHasNoPermissionsAtAllToDomainObject()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject, "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.setInternalMethod("getParent");
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        MethodInvocation mi = getMethodInvocation(domainObject);

        // NB: scott is the principal, not rod
        assertEquals(AccessDecisionVoter.ACCESS_DENIED,
                voter.vote(new UsernamePasswordAuthenticationToken("scott", null), mi, attr));
    }

    public void testVoterCanGrantAccessBasedOnInternalMethodOfDomainObject()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject.getParent(), "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.setInternalMethod("getParent");
        assertEquals("getParent", voter.getInternalMethod());
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        // (well actually it will access domainObject.getParent())
        MethodInvocation mi = getMethodInvocation(domainObject);

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr));
    }

    public void testVoterThrowsExceptionIfInvalidInternalMethodOfDomainObject()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject.getParent(), "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.setInternalMethod("getNonExistentParentName");
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation, so voter can retrieve domainObject
        // (well actually it will access domainObject.getParent())
        MethodInvocation mi = getMethodInvocation(domainObject);

        try {
            voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr);
            fail("Should have thrown AuthorizationServiceException");
        } catch (AuthorizationServiceException expected) {
            assertTrue(true);
        }
    }

    public void testVoterThrowsExceptionIfProcessDomainObjectNotFound()
        throws Exception {
        // Setup a domain object subject of this test
        SomeDomainObject domainObject = new SomeDomainObject("foo");

        // Setup an AclManager
        AclManager aclManager = new MockAclManager(domainObject.getParent(), "rod",
                new AclEntry[]{
                        new MockAclEntry(),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ),
                        new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.DELETE)
                });

        // Wire up a voter
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setAclManager(aclManager);
        voter.setProcessConfigAttribute("FOO_ADMIN_OR_WRITE_ACCESS");
        voter.setRequirePermission(new int[]{SimpleAclEntry.ADMINISTRATION, SimpleAclEntry.WRITE});
        voter.setProcessDomainObjectClass(SomeDomainObject.class);
        voter.afterPropertiesSet();

        // Wire up an invocation to be voted on
        ConfigAttributeDefinition attr = new ConfigAttributeDefinition("FOO_ADMIN_OR_WRITE_ACCESS");

        // Setup a MockMethodInvocation that doesn't provide SomeDomainObject arg
        Class clazz = String.class;
        Method method = clazz.getMethod("toString", new Class[]{});

        MethodInvocation mi = new SimpleMethodInvocation(method, new Object[]{domainObject});

        try {
            voter.vote(new UsernamePasswordAuthenticationToken("rod", null), mi, attr);
            fail("Should have thrown AuthorizationServiceException");
        } catch (AuthorizationServiceException expected) {
            assertTrue(true);
        }
    }

    public void testSetRequirePermissionFromString() {
        assertPermission("NOTHING", SimpleAclEntry.NOTHING);
        assertPermission("ADMINISTRATION", SimpleAclEntry.ADMINISTRATION);
        assertPermission("READ", SimpleAclEntry.READ);
        assertPermission("WRITE", SimpleAclEntry.WRITE);
        assertPermission("CREATE", SimpleAclEntry.CREATE);
        assertPermission("DELETE", SimpleAclEntry.DELETE);
        assertPermission(new String[] { "WRITE", "CREATE" }, new int[] { SimpleAclEntry.WRITE, SimpleAclEntry.CREATE });
    }

    public void testSetRequirePermissionFromStringWrongValues() {
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        try {
            voter.setRequirePermissionFromString(new String[] { "X" });
            fail(IllegalArgumentException.class.getName() + " must have been thrown.");
        } catch (IllegalArgumentException e) {
            // expected
        }
    }

    private void assertPermission(String text, int value) {
        assertPermission(new String[] { text }, new int[] { value });
    }

    private void assertPermission(String[] text, int[] value) {
        BasicAclEntryVoter voter = new BasicAclEntryVoter();
        voter.setRequirePermissionFromString(text);
        assertEquals("Test incorreclty coded", value.length, text.length);
        assertEquals(value.length, voter.getRequirePermission().length);
        for (int i = 0; i < value.length; i++) {
            assertEquals(value[i], voter.getRequirePermission()[i]);
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockAclEntry implements AclEntry {
        // just so AclTag iterates some different types of AclEntrys
    }
}
