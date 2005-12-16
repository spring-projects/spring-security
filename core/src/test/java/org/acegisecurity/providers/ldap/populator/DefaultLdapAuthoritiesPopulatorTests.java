package org.acegisecurity.providers.ldap.populator;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.BasicAttribute;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.providers.ldap.DefaultInitialDirContextFactory;

import java.util.Set;
import java.util.HashSet;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulatorTests extends AbstractLdapServerTestCase {
    private DefaultInitialDirContextFactory dirCtxFactory;
    private DefaultLdapAuthoritiesPopulator populator;

    public void setUp() {
        dirCtxFactory = new DefaultInitialDirContextFactory();
        dirCtxFactory.setUrl(PROVIDER_URL);
        dirCtxFactory.setInitialContextFactory(CONTEXT_FACTORY);
        dirCtxFactory.setExtraEnvVars(EXTRA_ENV);
        dirCtxFactory.setManagerDn(MANAGER_USER);
        dirCtxFactory.setManagerPassword(MANAGER_PASSWORD);

        populator = new DefaultLdapAuthoritiesPopulator();
        populator.setRolePrefix("ROLE_");
    }

    public void testCtxFactoryMustBeSetIfSearchBaseIsSet() throws Exception {
        populator.setGroupSearchBase("");

        try {
            populator.afterPropertiesSet();
            fail("expected exception.");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testUserAttributeMappingToRoles() {
        populator.setUserRoleAttributes(new String[] {"userRole", "otherUserRole"});
        populator.getUserRoleAttributes();

        Attributes userAttrs = new BasicAttributes();
        BasicAttribute attr = new BasicAttribute("userRole", "role1");
        attr.add("role2");
        userAttrs.put(attr);
        attr = new BasicAttribute("otherUserRole", "role3");
        attr.add("role2"); // duplicate
        userAttrs.put(attr);

        GrantedAuthority[] authorities = populator.getGrantedAuthorities("Ignored", "Ignored", userAttrs);
        assertEquals("User should have three roles", 3, authorities.length);
    }

    public void testGroupSearch() throws Exception {
        populator.setInitialDirContextFactory(dirCtxFactory);
        populator.setGroupSearchBase("ou=groups");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");
        populator.afterPropertiesSet();

        GrantedAuthority[] authorities = populator.getGrantedAuthorities("ben", "uid=ben,ou=people,"+ROOT_DN, new BasicAttributes());
        assertEquals("Should have 2 roles", 2, authorities.length);
        Set roles = new HashSet();
        roles.add(authorities[0].toString());
        roles.add(authorities[1].toString());
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_MANAGER"));
    }
}
