package org.springframework.security.userdetails.hierarchicalroles;

import java.util.List;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.util.AuthorityUtils;

/**
 * Tests for {@link UserDetailsWrapper}.
 *
 * @author Michael Mayr
 */
@SuppressWarnings("deprecation")
public class UserDetailsWrapperTests extends TestCase {

    private List<GrantedAuthority> authorities = null;
    private UserDetails userDetails1 = null;
    private UserDetails userDetails2 = null;
    private UserDetailsWrapper userDetailsWrapper1 = null;
    private UserDetailsWrapper userDetailsWrapper2 = null;

    public UserDetailsWrapperTests() {
    }

    public UserDetailsWrapperTests(String testCaseName) {
        super(testCaseName);
    }

    protected void setUp() throws Exception {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_A > ROLE_B");
        authorities = AuthorityUtils.createAuthorityList("ROLE_A");
        userDetails1 = new User("TestUser1", "TestPassword1", true, true, true, true, authorities);
        userDetails2 = new User("TestUser2", "TestPassword2", false, false, false, false, authorities);
        userDetailsWrapper1 = new UserDetailsWrapper(userDetails1, roleHierarchy);
        userDetailsWrapper2 = new UserDetailsWrapper(userDetails2, roleHierarchy);
    }

    public void testIsAccountNonExpired() {
        assertEquals(userDetails1.isAccountNonExpired(), userDetailsWrapper1.isAccountNonExpired());
        assertEquals(userDetails2.isAccountNonExpired(), userDetailsWrapper2.isAccountNonExpired());
    }

    public void testIsAccountNonLocked() {
        assertEquals(userDetails1.isAccountNonLocked(), userDetailsWrapper1.isAccountNonLocked());
        assertEquals(userDetails2.isAccountNonLocked(), userDetailsWrapper2.isAccountNonLocked());
    }

    public void testGetAuthorities() {
        List<GrantedAuthority> expectedAuthorities = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(userDetailsWrapper1.getAuthorities(), expectedAuthorities));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(userDetailsWrapper2.getAuthorities(), expectedAuthorities));
    }

    public void testIsCredentialsNonExpired() {
        assertEquals(userDetails1.isCredentialsNonExpired(), userDetailsWrapper1.isCredentialsNonExpired());
        assertEquals(userDetails2.isCredentialsNonExpired(), userDetailsWrapper2.isCredentialsNonExpired());
    }

    public void testIsEnabled() {
        assertEquals(userDetails1.isEnabled(), userDetailsWrapper1.isEnabled());
        assertEquals(userDetails2.isEnabled(), userDetailsWrapper2.isEnabled());
    }

    public void testGetPassword() {
        assertEquals(userDetails1.getPassword(), userDetailsWrapper1.getPassword());
        assertEquals(userDetails2.getPassword(), userDetailsWrapper2.getPassword());
    }

    public void testGetUsername() {
        assertEquals(userDetails1.getUsername(), userDetailsWrapper1.getUsername());
        assertEquals(userDetails2.getUsername(), userDetailsWrapper2.getUsername());
    }

    public void testGetUnwrappedUserDetails() {
        assertTrue(userDetailsWrapper1.getUnwrappedUserDetails() == userDetails1);
        assertTrue(userDetailsWrapper2.getUnwrappedUserDetails() == userDetails2);
    }

}
