package org.springframework.security.providers.preauth;

import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.User;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.GrantedAuthority;

import junit.framework.TestCase;

import org.springframework.dao.DataAccessException;

/**
 * 
 * @author TSARDD
 * @since 18-okt-2007
 */
public class UserDetailsByNameServiceWrapperTests extends TestCase {

	public final void testAfterPropertiesSet() {
		UserDetailsByNameServiceWrapper svc = new UserDetailsByNameServiceWrapper();
		try {
			svc.afterPropertiesSet();
			fail("AfterPropertiesSet didn't throw expected exception");
		} catch (IllegalArgumentException expected) {
		} catch (Exception unexpected) {
			fail("AfterPropertiesSet throws unexpected exception");
		}
	}

	public final void testGetUserDetails() throws Exception {
		UserDetailsByNameServiceWrapper svc = new UserDetailsByNameServiceWrapper();
		final User user = new User("dummy", "dummy", true, true, true, true, new GrantedAuthority[] { new GrantedAuthorityImpl("dummy") });
		svc.setUserDetailsService(new UserDetailsService() {
			public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException, DataAccessException {
				if (user != null && user.getUsername().equals(name)) {
					return user;
				} else {
					return null;
				}
			}
		});
		svc.afterPropertiesSet();
		UserDetails result1 = svc.loadUserDetails(new PreAuthenticatedAuthenticationToken("dummy", "dummy"));
		assertEquals("Result doesn't match original user", user, result1);
		UserDetails result2 = svc.loadUserDetails(new PreAuthenticatedAuthenticationToken("dummy2", "dummy"));
		assertNull("Result should have been null", result2);
	}

}
