package org.springframework.security.access.hierarchicalroles;

import static org.junit.Assert.*;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JMock;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RunWith(JMock.class)
@SuppressWarnings("deprecation")
public class UserDetailsServiceWrapperTests {

    private UserDetailsService wrappedUserDetailsService = null;
    private UserDetailsServiceWrapper userDetailsServiceWrapper = null;
    private Mockery jmockContext = new JUnit4Mockery();

    @Before
    public void setUp() throws Exception {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_A > ROLE_B");
        final UserDetails user = new User("EXISTING_USER", "PASSWORD", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_A"));
        final UserDetailsService wrappedUserDetailsService = jmockContext.mock(UserDetailsService.class);

        jmockContext.checking( new Expectations() {{
            allowing(wrappedUserDetailsService).loadUserByUsername("EXISTING_USER"); will(returnValue(user));
            allowing(wrappedUserDetailsService).loadUserByUsername("USERNAME_NOT_FOUND_EXCEPTION"); will(throwException(new UsernameNotFoundException("USERNAME_NOT_FOUND_EXCEPTION")));
        }});
        this.wrappedUserDetailsService = wrappedUserDetailsService;
        userDetailsServiceWrapper = new UserDetailsServiceWrapper();
        userDetailsServiceWrapper.setRoleHierarchy(roleHierarchy);
        userDetailsServiceWrapper.setUserDetailsService(wrappedUserDetailsService);
    }

    @Test
    public void testLoadUserByUsername() {
        UserDetails expectedUserDetails = new User("EXISTING_USER", "PASSWORD", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B"));
        UserDetails userDetails = userDetailsServiceWrapper.loadUserByUsername("EXISTING_USER");
        assertEquals(expectedUserDetails.getPassword(), userDetails.getPassword());
        assertEquals(expectedUserDetails.getUsername(), userDetails.getUsername());
        assertEquals(expectedUserDetails.isAccountNonExpired(), userDetails.isAccountNonExpired());
        assertEquals(expectedUserDetails.isAccountNonLocked(), userDetails.isAccountNonLocked());
        assertEquals(expectedUserDetails.isCredentialsNonExpired(), expectedUserDetails.isCredentialsNonExpired());
        assertEquals(expectedUserDetails.isEnabled(), userDetails.isEnabled());
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(expectedUserDetails.getAuthorities(), userDetails.getAuthorities()));

        try {
            userDetails = userDetailsServiceWrapper.loadUserByUsername("USERNAME_NOT_FOUND_EXCEPTION");
            fail("testLoadUserByUsername() - UsernameNotFoundException did not bubble up!");
        } catch (UsernameNotFoundException e) {}
    }

    @Test
    public void testGetWrappedUserDetailsService() {
        assertTrue(userDetailsServiceWrapper.getWrappedUserDetailsService() == wrappedUserDetailsService);
    }
}
