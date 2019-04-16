/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.web.servlet.request;

import java.util.Enumeration;

import org.junit.Before;
import org.mockito.Mock;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public abstract class AbstractRequestPostProcessorTests {

	@Mock
	MockHttpServletRequest request;

	final static String TEST_NAME = "ch4mpy";
	final static String[] TEST_AUTHORITIES = new String[] { "TEST_AUTHORITY" };

	@Before
	public void setup() throws Exception {
		request = new MockHttpServletRequest();
	}

	static Authentication authentication(final MockHttpServletRequest req) {
		for (final Enumeration<String> names = req.getAttributeNames(); names.hasMoreElements();) {
			final String name = names.nextElement();
			if (name.contains("SecurityContext")) {
				final SecurityContext securityContext = (SecurityContext) req.getAttribute(name);
				return securityContext.getAuthentication();
			}
		}
		return null;
	}

}
