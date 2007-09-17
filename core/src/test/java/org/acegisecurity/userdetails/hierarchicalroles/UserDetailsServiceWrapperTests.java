package org.acegisecurity.userdetails.hierarchicalroles;

import junit.textui.TestRunner;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jmock.Mock;
import org.jmock.MockObjectTestCase;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;

public class UserDetailsServiceWrapperTests extends MockObjectTestCase {

    private UserDetailsService wrappedUserDetailsService = null;
    private UserDetailsServiceWrapper userDetailsServiceWrapper = null;
    
    public UserDetailsServiceWrapperTests() {
        super();
    }

    public UserDetailsServiceWrapperTests(String testCaseName) {
        super(testCaseName);
    }

    public static void main(String[] args) {
        TestRunner.run(UserDetailsServiceWrapperTests.class);
    }

    protected void setUp() throws Exception {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_A > ROLE_B");
        GrantedAuthority[] authorities = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A") };
        UserDetails user = new User("EXISTING_USER", "PASSWORD", true, true, true, true, authorities);
        Mock wrappedUserDetailsServiceMock = mock(UserDetailsService.class);
        wrappedUserDetailsServiceMock.stubs().method("loadUserByUsername").with(eq("EXISTING_USER")).will(returnValue(user));
        wrappedUserDetailsServiceMock.stubs().method("loadUserByUsername").with(eq("USERNAME_NOT_FOUND_EXCEPTION")).will(throwException(new UsernameNotFoundException("USERNAME_NOT_FOUND_EXCEPTION")));
        wrappedUserDetailsServiceMock.stubs().method("loadUserByUsername").with(eq("DATA_ACCESS_EXCEPTION")).will(throwException(new EmptyResultDataAccessException(1234)));
        wrappedUserDetailsService = (UserDetailsService) wrappedUserDetailsServiceMock.proxy();
        userDetailsServiceWrapper = new UserDetailsServiceWrapper();
        userDetailsServiceWrapper.setRoleHierarchy(roleHierarchy);
        userDetailsServiceWrapper.setUserDetailsService(wrappedUserDetailsService);
    }

    public void testLoadUserByUsername() {
        GrantedAuthority[] authorities = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B") };
        UserDetails expectedUserDetails = new User("EXISTING_USER", "PASSWORD", true, true, true, true, authorities);
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
        
        try {
            userDetails = userDetailsServiceWrapper.loadUserByUsername("DATA_ACCESS_EXCEPTION");
            fail("testLoadUserByUsername() - DataAccessException did not bubble up!");
        } catch (DataAccessException e) {}
    }
    
    public void testGetWrappedUserDetailsService() {
        assertTrue(userDetailsServiceWrapper.getWrappedUserDetailsService() == wrappedUserDetailsService);
    }
   
}