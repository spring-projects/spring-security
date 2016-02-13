package org.springframework.security.core.userdetails;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
@SuppressWarnings("unchecked")
public class UserDetailsByNameServiceWrapperTests  {

	@Test
	public final void testAfterPropertiesSet() {
		UserDetailsByNameServiceWrapper svc = new UserDetailsByNameServiceWrapper();
		try {
			svc.afterPropertiesSet();
			fail("AfterPropertiesSet didn't throw expected exception");
		}
		catch (IllegalArgumentException expected) {
		}
		catch (Exception unexpected) {
			fail("AfterPropertiesSet throws unexpected exception");
		}
	}

	@Test
	public final void testGetUserDetails() throws Exception {
		UserDetailsByNameServiceWrapper svc = new UserDetailsByNameServiceWrapper();
		final User user = new User("dummy", "dummy", true, true, true, true,
				AuthorityUtils.NO_AUTHORITIES);
		svc.setUserDetailsService(new UserDetailsService() {
			public UserDetails loadUserByUsername(String name) {
				if (user != null && user.getUsername().equals(name)) {
					return user;
				}
				else {
					return null;
				}
			}
		});
		svc.afterPropertiesSet();
		UserDetails result1 = svc.loadUserDetails(new TestingAuthenticationToken("dummy",
				"dummy"));
		assertThat(result1).as("Result doesn't match original user").isEqualTo(user);
		UserDetails result2 = svc.loadUserDetails(new TestingAuthenticationToken(
				"dummy2", "dummy"));
		assertThat(result2).as("Result should have been null").isNull();
	}

}
