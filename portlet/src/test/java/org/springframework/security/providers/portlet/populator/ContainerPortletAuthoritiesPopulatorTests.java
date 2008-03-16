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

package org.springframework.security.providers.portlet.populator;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.portlet.PortletAuthenticationToken;
import org.springframework.security.providers.portlet.PortletTestUtils;
import org.springframework.security.userdetails.UserDetails;


/**
 * Tests for {@link ContainerPortletAuthoritiesPopulator}
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class ContainerPortletAuthoritiesPopulatorTests extends TestCase {

	//~ Constructors ===================================================================================================

	public ContainerPortletAuthoritiesPopulatorTests() {
		super();
	}

	public ContainerPortletAuthoritiesPopulatorTests(String arg0) {
		super(arg0);
	}

	//~ Methods ========================================================================================================

	public final void setUp() throws Exception {
		super.setUp();
	}

	private List createRolesToCheck() {
		ArrayList rolesToCheck = new ArrayList();
		rolesToCheck.add(PortletTestUtils.PORTALROLE1);
		rolesToCheck.add("BOGUS1");
		rolesToCheck.add(PortletTestUtils.PORTALROLE2);
		rolesToCheck.add("BOGUS2");
		return rolesToCheck;
	}

	public void testGetGrantedAuthorities() throws Exception {
		ContainerPortletAuthoritiesPopulator populator = new ContainerPortletAuthoritiesPopulator();
		UserDetails results = populator.getUserDetails(PortletTestUtils.createToken());
		assertEquals(1, results.getAuthorities().length);
		assertEquals(new GrantedAuthorityImpl(ContainerPortletAuthoritiesPopulator.DEFAULT_USER_ROLE), results.getAuthorities()[0]);
	}

	public void testGetGrantedAuthoritiesCheckRoles() throws Exception {
		ContainerPortletAuthoritiesPopulator populator = new ContainerPortletAuthoritiesPopulator();
		populator.setRolesToCheck(createRolesToCheck());
		UserDetails results = populator.getUserDetails(PortletTestUtils.createToken());
		assertEquals(3, results.getAuthorities().length);
		assertEquals(new GrantedAuthorityImpl(ContainerPortletAuthoritiesPopulator.DEFAULT_USER_ROLE), results.getAuthorities()[2]);
		assertEquals(new GrantedAuthorityImpl(PortletTestUtils.TESTROLE1), results.getAuthorities()[0]);
		assertEquals(new GrantedAuthorityImpl(PortletTestUtils.TESTROLE2), results.getAuthorities()[1]);
	}

	public void testGetGrantedAuthoritiesCustomPrefix() throws Exception {
		String prefix = "IHAVE_";
		ContainerPortletAuthoritiesPopulator populator = new ContainerPortletAuthoritiesPopulator();
		populator.setRolesToCheck(createRolesToCheck());
		populator.setRolePrefix(prefix);
		UserDetails results = populator.getUserDetails(PortletTestUtils.createToken());
		assertEquals(3, results.getAuthorities().length);
		assertEquals(new GrantedAuthorityImpl(ContainerPortletAuthoritiesPopulator.DEFAULT_USER_ROLE), results.getAuthorities()[2]);
		assertEquals(new GrantedAuthorityImpl(prefix + PortletTestUtils.PORTALROLE1), results.getAuthorities()[0]);
		assertEquals(new GrantedAuthorityImpl(prefix + PortletTestUtils.PORTALROLE2), results.getAuthorities()[1]);
	}

	public void testGetGrantedAuthoritiesNullDefault() throws Exception {
		ContainerPortletAuthoritiesPopulator populator = new ContainerPortletAuthoritiesPopulator();
		populator.setUserRole(null);
		UserDetails results = populator.getUserDetails(PortletTestUtils.createToken());
		assertEquals(0, results.getAuthorities().length);
	}

	public void testGetGrantedAuthoritiesEmptyDefault() throws Exception {
		ContainerPortletAuthoritiesPopulator populator = new ContainerPortletAuthoritiesPopulator();
		populator.setUserRole("");
		UserDetails results = populator.getUserDetails(PortletTestUtils.createToken());
		assertEquals(0, results.getAuthorities().length);
	}

	public void testGetGrantedAuthoritiesForInvalidToken() throws Exception {
		ContainerPortletAuthoritiesPopulator populator = new ContainerPortletAuthoritiesPopulator();
		PortletAuthenticationToken token = PortletTestUtils.createToken();
		token.setDetails(null);
		try {
			populator.getUserDetails(token);
			fail("Should have thrown AuthenticationServiceException");
		} catch (AuthenticationServiceException e) {
			// ignore
		}
		token.setDetails("bogus");
		try {
			populator.getUserDetails(token);
			fail("Should have thrown AuthenticationServiceException");
		} catch (AuthenticationServiceException e) {
			// ignore
		}
	}

}
