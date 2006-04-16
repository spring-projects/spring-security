package org.acegisecurity.providers.ldap.populator;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.BasicAttribute;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.AbstractLdapServerTestCase;

import java.util.Set;
import java.util.HashSet;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulatorTests extends AbstractLdapServerTestCase {

    public void onSetUp() {
        getInitialCtxFactory().setManagerDn(MANAGER_USER);
        getInitialCtxFactory().setManagerPassword(MANAGER_PASSWORD);
    }

    public void testUserAttributeMappingToRoles() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator();
        populator.setUserRoleAttributes(new String[] {"userRole", "otherUserRole"});
        populator.getUserRoleAttributes();

        Attributes userAttrs = new BasicAttributes();
        BasicAttribute attr = new BasicAttribute("userRole", "role1");
        attr.add("role2");
        userAttrs.put(attr);
        attr = new BasicAttribute("otherUserRole", "role3");
        attr.add("role2"); // duplicate
        userAttrs.put(attr);

        GrantedAuthority[] authorities =
                populator.getGrantedAuthorities("Ignored", "Ignored", userAttrs);
        assertEquals("User should have three roles", 3, authorities.length);
    }

    public void testDefaultRoleIsAssignedWhenSet() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator();
        populator.setDefaultRole("ROLE_USER");

        GrantedAuthority[] authorities =
                populator.getGrantedAuthorities("Ignored", "Ignored", new BasicAttributes());
        assertEquals(1, authorities.length);
        assertEquals("ROLE_USER", authorities[0].getAuthority());
    }

    public void testGroupSearch() throws Exception {
        DefaultLdapAuthoritiesPopulator populator =
                new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(), "ou=groups");
        populator.setRolePrefix("ROLE_");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        GrantedAuthority[] authorities =
                populator.getGrantedAuthorities("ben", "uid=ben,ou=people,"+
                        getInitialCtxFactory().getRootDn(), new BasicAttributes());
        assertEquals("Should have 2 roles", 2, authorities.length);
        Set roles = new HashSet();
        roles.add(authorities[0].toString());
        roles.add(authorities[1].toString());
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_MANAGER"));
    }
}
