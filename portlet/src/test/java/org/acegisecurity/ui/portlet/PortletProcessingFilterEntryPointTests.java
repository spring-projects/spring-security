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

package org.springframework.security.ui.portlet;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

import org.springframework.security.BadCredentialsException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Tests {@link PortletProcessingFilterEntryPoint}.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletProcessingFilterEntryPointTests extends TestCase {

	//~ Constructors ===================================================================================================

	public PortletProcessingFilterEntryPointTests() {
		super();
	}

	public PortletProcessingFilterEntryPointTests(String arg0) {
		super(arg0);
	}

	//~ Methods ========================================================================================================

	public final void setUp() throws Exception {
		super.setUp();
	}

	public void testNormalOperation() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		PortletProcessingFilterEntryPoint entryPoint = new PortletProcessingFilterEntryPoint();
		entryPoint.commence(request, response, new BadCredentialsException(null));
		assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
	}

}
