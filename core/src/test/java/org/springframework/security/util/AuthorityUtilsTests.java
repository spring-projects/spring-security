package org.springframework.security.util;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthorityUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthorityUtilsTests {

    @Before
    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void userHasAuthorityReturnsFalseForUnauthenticatedUser() {
        assertFalse(AuthorityUtils.userHasAuthority("SOME_AUTHORITY"));
    }

    @Test
    public void userHasAuthorityReturnsFalseWhenUserHasNoAuthorities() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("user", "password"));
        assertFalse(AuthorityUtils.userHasAuthority("SOME_AUTHORITY"));
    }

    @Test
    public void userHasAuthorityReturnsTrueWhenUserHasCorrectAuthority() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", "password",
                AuthorityUtils.createAuthorityList("A", "B")));
        assertTrue(AuthorityUtils.userHasAuthority("A"));
        assertTrue(AuthorityUtils.userHasAuthority("B"));
        assertFalse(AuthorityUtils.userHasAuthority("C"));
    }

    @Test
    public void commaSeparatedStringIsParsedCorrectly() {
        List<GrantedAuthority> authorityArray =
                AuthorityUtils.commaSeparatedStringToAuthorityList(" ROLE_A, B, C, ROLE_D, E ");

        Set<String> authorities = AuthorityUtils.authorityListToSet(authorityArray);

        assertTrue(authorities.contains("B"));
        assertTrue(authorities.contains("C"));
        assertTrue(authorities.contains("E"));
        assertTrue(authorities.contains("ROLE_A"));
        assertTrue(authorities.contains("ROLE_D"));
    }
}
