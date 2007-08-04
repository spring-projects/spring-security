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

package org.acegisecurity.providers.portlet;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;

/**
 * Tests {@link PortletAuthenticationProvider}
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletAuthenticationProviderTests extends TestCase {

	//~ Constructors ===================================================================================================

	public PortletAuthenticationProviderTests() {
		super();
	}

	public PortletAuthenticationProviderTests(String arg0) {
		super(arg0);
	}

	//~ Methods ========================================================================================================

	public void testRequiresPopulator() throws Exception {
		PortletAuthenticationProvider provider = new PortletAuthenticationProvider();
		try {
			provider.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException failed) {
			//ignored
		}
	}

	public void testNormalOperation() throws Exception {
		PortletAuthenticationProvider provider = new PortletAuthenticationProvider();
		provider.setPortletAuthoritiesPopulator(new MockAuthoritiesPopulator(false));
		provider.afterPropertiesSet();
		Authentication result = provider.authenticate(PortletTestUtils.createToken());
		assertNotNull(result);
		assertNotNull(result.getAuthorities());
	}

	public void testAuthenticationIsNullWithUnsupportedToken() {
		PortletAuthenticationProvider provider = new PortletAuthenticationProvider();
		Authentication request = new UsernamePasswordAuthenticationToken(PortletTestUtils.TESTUSER, PortletTestUtils.TESTCRED);
		Authentication result = provider.authenticate(request);
		assertNull(result);
	}

	public void testFailsWithNoCredentials() {
		PortletAuthenticationProvider provider = new PortletAuthenticationProvider();
		provider.setPortletAuthoritiesPopulator(new MockAuthoritiesPopulator(false));
		try {
			provider.authenticate(new PortletAuthenticationToken(PortletTestUtils.TESTUSER, null, null));
			fail("Should have thrown BadCredentialsException");
		} catch (BadCredentialsException e) {
			//ignore
		}
	}

	public void testPopulatorRejectionCausesFailure() throws Exception {
		PortletAuthenticationProvider provider = new PortletAuthenticationProvider();
		provider.setPortletAuthoritiesPopulator(new MockAuthoritiesPopulator(true));
		try {
			provider.authenticate(PortletTestUtils.createToken());
			fail("Should have thrown BadCredentialsException");
		} catch (BadCredentialsException e) {
			//ignore
		}
	}

	//~ Inner Classes ==================================================================================================

	public static class MockAuthoritiesPopulator implements PortletAuthoritiesPopulator {

		private boolean reject = false;

		public MockAuthoritiesPopulator (boolean reject) {
			this.reject = reject;
		}

		public UserDetails getUserDetails(Authentication authentication)
			throws AuthenticationException {
			if (authentication.getCredentials() == null)
				throw new BadCredentialsException("Invalid Credentials");
			if (reject)
				throw new BadCredentialsException("Authentication Rejected");
			return PortletTestUtils.createUser();
		}

	}

}
