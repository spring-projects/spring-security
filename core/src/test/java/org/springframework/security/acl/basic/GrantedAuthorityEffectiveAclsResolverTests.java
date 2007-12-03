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

package org.springframework.security.acl.basic;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.acl.AclEntry;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.security.userdetails.User;


/**
 * Tests {@link GrantedAuthorityEffectiveAclsResolver}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GrantedAuthorityEffectiveAclsResolverTests extends TestCase {
    //~ Instance fields ================================================================================================

    private SimpleAclEntry entry100RoleEverybody = new SimpleAclEntry("ROLE_EVERYBODY",
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 14);
    private SimpleAclEntry entry100RoleOne = new SimpleAclEntry("ROLE_ONE",
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 0);
    private SimpleAclEntry entry100RoleTwo = new SimpleAclEntry("ROLE_TWO",
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 2);
    private UsernamePasswordAuthenticationToken scott = new UsernamePasswordAuthenticationToken("scott", "not used",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY"), new GrantedAuthorityImpl("ROLE_TWO")});
    private SimpleAclEntry entry100Scott = new SimpleAclEntry(scott.getPrincipal(),
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 4);
    private UsernamePasswordAuthenticationToken dianne = new UsernamePasswordAuthenticationToken("dianne", "not used");
    private UsernamePasswordAuthenticationToken rod = new UsernamePasswordAuthenticationToken("rod",
            "not used",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY"), new GrantedAuthorityImpl("ROLE_ONE")});
    private SimpleAclEntry entry100rod = new SimpleAclEntry(rod.getPrincipal(),
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 2);
    private UsernamePasswordAuthenticationToken scottWithUserDetails = new UsernamePasswordAuthenticationToken(new User(
                "scott", "NOT_USED", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY")}), "not used",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY"), new GrantedAuthorityImpl("ROLE_TWO")});

    // convenience group
    private SimpleAclEntry[] acls = {
            entry100rod, entry100Scott, entry100RoleEverybody, entry100RoleOne, entry100RoleTwo
        };

    //~ Constructors ===================================================================================================

    public GrantedAuthorityEffectiveAclsResolverTests() {
        super();
    }

    public GrantedAuthorityEffectiveAclsResolverTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(GrantedAuthorityEffectiveAclsResolverTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testResolveAclsForDianneWhoHasANullForAuthorities() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertNull(resolver.resolveEffectiveAcls(acls, dianne));
    }

    public void testResolveAclsForrod() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertEquals(3, resolver.resolveEffectiveAcls(acls, rod).length);
        assertEquals(entry100rod, resolver.resolveEffectiveAcls(acls, rod)[0]);
        assertEquals(entry100RoleEverybody, resolver.resolveEffectiveAcls(acls, rod)[1]);
        assertEquals(entry100RoleOne, resolver.resolveEffectiveAcls(acls, rod)[2]);
    }

    public void testResolveAclsForScottWithStringObjectAsPrincipal() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertEquals(3, resolver.resolveEffectiveAcls(acls, scott).length);
        assertEquals(entry100Scott, resolver.resolveEffectiveAcls(acls, scott)[0]);
        assertEquals(entry100RoleEverybody, resolver.resolveEffectiveAcls(acls, scott)[1]);
        assertEquals(entry100RoleTwo, resolver.resolveEffectiveAcls(acls, scott)[2]);
    }

    public void testResolveAclsForScottWithUserDetailsObjectAsPrincipal() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertEquals(3, resolver.resolveEffectiveAcls(acls, scottWithUserDetails).length);
        assertEquals(entry100Scott, resolver.resolveEffectiveAcls(acls, scottWithUserDetails)[0]);
        assertEquals(entry100RoleEverybody, resolver.resolveEffectiveAcls(acls, scottWithUserDetails)[1]);
        assertEquals(entry100RoleTwo, resolver.resolveEffectiveAcls(acls, scottWithUserDetails)[2]);
    }

    public void testResolveAclsReturnsNullIfNoAclsInFirstPlace() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertNull(resolver.resolveEffectiveAcls(null, scott));
    }

    public void testSkipsNonBasicAclEntryObjects() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        AclEntry[] basicAcls = {
                entry100rod, entry100Scott, entry100RoleEverybody, entry100RoleOne, new MockAcl(), entry100RoleTwo
            };
        assertEquals(3, resolver.resolveEffectiveAcls(basicAcls, rod).length);
    }

    //~ Inner Classes ==================================================================================================

    private class MockAcl implements AclEntry {
        // does nothing
    }
}
