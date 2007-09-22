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

package org.springframework.security.providers.portlet;

import junit.framework.TestCase;

/**
 * Tests for {@link PortletAuthenticationToken}.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletAuthenticationTokenTests extends TestCase {

	//~ Constructors ===================================================================================================

	public PortletAuthenticationTokenTests() {}

	public PortletAuthenticationTokenTests(String s) {
		super(s);
	}

	//~ Methods ========================================================================================================

	public void setUp() throws Exception {
		super.setUp();
	}

	public void testPrincipal() throws Exception {
		PortletAuthenticationToken token = PortletTestUtils.createToken();
		assertEquals(PortletTestUtils.TESTUSER, token.getPrincipal());
	}

	public void testCredentials() throws Exception {
		PortletAuthenticationToken token = PortletTestUtils.createToken();
		assertEquals(PortletTestUtils.TESTCRED, token.getCredentials());
	}

	public void testAuthenticated() throws Exception {
		PortletAuthenticationToken token = PortletTestUtils.createToken();
		assertTrue(!token.isAuthenticated());
		token.setAuthenticated(true);
		assertTrue(token.isAuthenticated());
		token.setAuthenticated(false);
		assertTrue(!token.isAuthenticated());
	}

}
