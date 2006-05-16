package org.acegisecurity.providers.ldap.populator;

import javax.naming.directory.BasicAttributes;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
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

//    public void testUserAttributeMappingToRoles() {
//        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator();
//        populator.setUserRoleAttributes(new String[] {"userRole", "otherUserRole"});
//        populator.getUserRoleAttributes();
//
//        Attributes userAttrs = new BasicAttributes();
//        BasicAttribute attr = new BasicAttribute("userRole", "role1");
//        attr.add("role2");
//        userAttrs.put(attr);
//        attr = new BasicAttribute("otherUserRole", "role3");
//        attr.add("role2"); // duplicate
//        userAttrs.put(attr);
//
//        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
//        user.setDn("Ignored");
//        user.setUsername("Ignored");
//        user.setAttributes(userAttrs);
//
//        GrantedAuthority[] authorities =
//                populator.getGrantedAuthorities(user.createUserDetails());
//        assertEquals("User should have three roles", 3, authorities.length);
//    }

    public void testDefaultRoleIsAssignedWhenSet() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(), "ou=groups");
        populator.setDefaultRole("ROLE_USER");
        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setDn("cn=notfound");
        user.setUsername("notfound");
        user.setAttributes(new BasicAttributes());

        GrantedAuthority[] authorities =
                populator.getGrantedAuthorities(user.createUserDetails());
        assertEquals(1, authorities.length);
        assertEquals("ROLE_USER", authorities[0].getAuthority());
    }

    public void testGroupSearchReturnsExpectedRoles() {
        DefaultLdapAuthoritiesPopulator populator =
                new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(), "ou=groups");
        populator.setRolePrefix("ROLE_");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setUsername("ben");
        user.setDn("uid=ben,ou=people,dc=acegisecurity,dc=org");
        user.setAttributes(new BasicAttributes());

        GrantedAuthority[] authorities =
                populator.getGrantedAuthorities(user.createUserDetails());

        assertEquals("Should have 2 roles", 2, authorities.length);
        Set roles = new HashSet();
        roles.add(authorities[0].toString());
        roles.add(authorities[1].toString());
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_MANAGER"));
    }
}
