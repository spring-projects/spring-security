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

package net.sf.acegisecurity.acl.basic;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.acl.AclEntry;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.providers.dao.User;


/**
 * Tests {@link GrantedAuthorityEffectiveAclsResolver}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GrantedAuthorityEffectiveAclsResolverTests extends TestCase {
    //~ Instance fields ========================================================

    private SimpleAclEntry entry100RoleEverybody = new SimpleAclEntry("ROLE_EVERYBODY",
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 14);
    private SimpleAclEntry entry100RoleOne = new SimpleAclEntry("ROLE_ONE",
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 0);
    private SimpleAclEntry entry100RoleTwo = new SimpleAclEntry("ROLE_TWO",
            new NamedEntityObjectIdentity("OBJECT", "100"), null, 2);
    private UsernamePasswordAuthenticationToken scott = new UsernamePasswordAuthenticationToken("scott",
            "not used",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY"), new GrantedAuthorityImpl(
                    "ROLE_TWO")});
    private SimpleAclEntry entry100Scott = new SimpleAclEntry(scott
            .getPrincipal(), new NamedEntityObjectIdentity("OBJECT", "100"),
            null, 4);
    private UsernamePasswordAuthenticationToken dianne = new UsernamePasswordAuthenticationToken("dianne",
            "not used");
    private UsernamePasswordAuthenticationToken marissa = new UsernamePasswordAuthenticationToken("marissa",
            "not used",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY"), new GrantedAuthorityImpl("ROLE_ONE")});
    private SimpleAclEntry entry100Marissa = new SimpleAclEntry(marissa
            .getPrincipal(), new NamedEntityObjectIdentity("OBJECT", "100"),
            null, 2);
    private UsernamePasswordAuthenticationToken scottWithUserDetails = new UsernamePasswordAuthenticationToken(new User(
                "scott", "NOT_USED", true,
                new GrantedAuthority[] {new GrantedAuthorityImpl(
                        "ROLE_EVERYBODY")}), "not used",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_EVERYBODY"), new GrantedAuthorityImpl("ROLE_TWO")});

    // convenience group
    private SimpleAclEntry[] acls = {entry100Marissa, entry100Scott, entry100RoleEverybody, entry100RoleOne, entry100RoleTwo};

    //~ Constructors ===========================================================

    public GrantedAuthorityEffectiveAclsResolverTests() {
        super();
    }

    public GrantedAuthorityEffectiveAclsResolverTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(GrantedAuthorityEffectiveAclsResolverTests.class);
    }

    public void testResolveAclsForDianneWhoHasANullForAuthorities() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertNull(resolver.resolveEffectiveAcls(acls, dianne));
    }

    public void testResolveAclsForMarissa() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertEquals(3, resolver.resolveEffectiveAcls(acls, marissa).length);
        assertEquals(entry100Marissa,
            resolver.resolveEffectiveAcls(acls, marissa)[0]);
        assertEquals(entry100RoleEverybody,
            resolver.resolveEffectiveAcls(acls, marissa)[1]);
        assertEquals(entry100RoleOne,
            resolver.resolveEffectiveAcls(acls, marissa)[2]);
    }

    public void testResolveAclsForScottWithStringObjectAsPrincipal() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertEquals(3, resolver.resolveEffectiveAcls(acls, scott).length);
        assertEquals(entry100Scott,
            resolver.resolveEffectiveAcls(acls, scott)[0]);
        assertEquals(entry100RoleEverybody,
            resolver.resolveEffectiveAcls(acls, scott)[1]);
        assertEquals(entry100RoleTwo,
            resolver.resolveEffectiveAcls(acls, scott)[2]);
    }

    public void testResolveAclsForScottWithUserDetailsObjectAsPrincipal() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertEquals(3,
            resolver.resolveEffectiveAcls(acls, scottWithUserDetails).length);
        assertEquals(entry100Scott,
            resolver.resolveEffectiveAcls(acls, scottWithUserDetails)[0]);
        assertEquals(entry100RoleEverybody,
            resolver.resolveEffectiveAcls(acls, scottWithUserDetails)[1]);
        assertEquals(entry100RoleTwo,
            resolver.resolveEffectiveAcls(acls, scottWithUserDetails)[2]);
    }

    public void testResolveAclsReturnsNullIfNoAclsInFirstPlace() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        assertNull(resolver.resolveEffectiveAcls(null, scott));
    }

    public void testSkipsNonBasicAclEntryObjects() {
        GrantedAuthorityEffectiveAclsResolver resolver = new GrantedAuthorityEffectiveAclsResolver();
        AclEntry[] basicAcls = {entry100Marissa, entry100Scott, entry100RoleEverybody, entry100RoleOne, new MockAcl(), entry100RoleTwo};
        assertEquals(3, resolver.resolveEffectiveAcls(basicAcls, marissa).length);
    }

    //~ Inner Classes ==========================================================

    private class MockAcl implements AclEntry {
        // does nothing
    }
}
