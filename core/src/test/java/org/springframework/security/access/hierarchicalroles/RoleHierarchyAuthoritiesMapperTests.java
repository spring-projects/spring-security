package org.springframework.security.access.hierarchicalroles;

import static junit.framework.Assert.assertEquals;

import org.junit.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class RoleHierarchyAuthoritiesMapperTests {

    @Test
    public void expectedAuthoritiesAreReturned() {
        RoleHierarchyImpl rh = new RoleHierarchyImpl();
        rh.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C");
        RoleHierarchyAuthoritiesMapper mapper = new RoleHierarchyAuthoritiesMapper(rh);

        Collection<? extends GrantedAuthority> authorities =
                mapper.mapAuthorities(AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_D"));

        assertEquals(4, authorities.size());

        mapper = new RoleHierarchyAuthoritiesMapper(new NullRoleHierarchy());

        authorities = mapper.mapAuthorities(AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_D"));

        assertEquals(2, authorities.size());
    }
}
