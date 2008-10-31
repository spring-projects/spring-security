package org.springframework.security.util;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.junit.After;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Set;

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
        GrantedAuthority[] authorityArray =
                AuthorityUtils.commaSeparatedStringToAuthorityArray(" ROLE_A, B, C, ROLE_D, E ");

        Set authorities = AuthorityUtils.authorityArrayToSet(Arrays.asList(authorityArray));

        assertTrue(authorities.contains("B"));
        assertTrue(authorities.contains("C"));
        assertTrue(authorities.contains("E"));
        assertTrue(authorities.contains("ROLE_A"));
        assertTrue(authorities.contains("ROLE_D"));
    }


}
