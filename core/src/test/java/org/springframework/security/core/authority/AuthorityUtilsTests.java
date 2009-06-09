package org.springframework.security.core.authority;

import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthorityUtilsTests {

    @Test
    public void commaSeparatedStringIsParsedCorrectly() {
        List<GrantedAuthority> authorityArray =
                AuthorityUtils.commaSeparatedStringToAuthorityList(" ROLE_A, B, C, ROLE_D\n,\n E ");

        Set<String> authorities = AuthorityUtils.authorityListToSet(authorityArray);

        assertTrue(authorities.contains("B"));
        assertTrue(authorities.contains("C"));
        assertTrue(authorities.contains("E"));
        assertTrue(authorities.contains("ROLE_A"));
        assertTrue(authorities.contains("ROLE_D"));
    }
}
