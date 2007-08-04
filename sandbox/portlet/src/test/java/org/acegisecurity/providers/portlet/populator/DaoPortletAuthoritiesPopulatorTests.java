/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.portlet.populator;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.portlet.PortletAuthenticationToken;
import org.acegisecurity.providers.portlet.PortletTestUtils;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;


/**
 * Tests for {@link DaoPortletAuthoritiesPopulator}
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class DaoPortletAuthoritiesPopulatorTests extends TestCase {

	//~ Constructors ===================================================================================================

	public DaoPortletAuthoritiesPopulatorTests() {
		super();
	}

	public DaoPortletAuthoritiesPopulatorTests(String arg0) {
		super(arg0);
	}

	//~ Methods ========================================================================================================

	public final void setUp() throws Exception {
		super.setUp();
	}

	public void testRequiresDao() throws Exception {
		DaoPortletAuthoritiesPopulator populator = new DaoPortletAuthoritiesPopulator();
		try {
			populator.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException failed) {
			// ignored
		}
	}

	public void testGetGrantedAuthoritiesForValidUser() throws Exception {
		DaoPortletAuthoritiesPopulator populator = new DaoPortletAuthoritiesPopulator();
		populator.setUserDetailsService(new MockAuthenticationDao());
		populator.afterPropertiesSet();
		UserDetails results = populator.getUserDetails(PortletTestUtils.createToken());
		assertEquals(2, results.getAuthorities().length);
		assertEquals(new GrantedAuthorityImpl(PortletTestUtils.TESTROLE1), results.getAuthorities()[0]);
		assertEquals(new GrantedAuthorityImpl(PortletTestUtils.TESTROLE2), results.getAuthorities()[1]);
	}

	public void testGetGrantedAuthoritiesForInvalidUser() throws Exception {
		DaoPortletAuthoritiesPopulator populator = new DaoPortletAuthoritiesPopulator();
		populator.setUserDetailsService(new MockAuthenticationDao());
		populator.afterPropertiesSet();
		try {
			populator.getUserDetails(new PortletAuthenticationToken("dummy", "dummy", null));
			fail("Should have thrown UsernameNotFoundException");
		} catch (UsernameNotFoundException e) {
			// ignore
		}
	}

	//~ Inner Classes ==================================================================================================

	private class MockAuthenticationDao implements UserDetailsService {

		public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException, DataAccessException {
			if (PortletTestUtils.TESTUSER.equals(username))
				return PortletTestUtils.createUser();
			throw new UsernameNotFoundException("Could not find: " + username);
		}

	}

}
