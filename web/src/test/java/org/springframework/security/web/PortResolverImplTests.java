/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link PortResolverImpl}.
 *
 * @author Ben Alex
 */
public class PortResolverImplTests {

	@Test
	public void testDetectsBuggyIeHttpRequest() {
		PortResolverImpl pr = new PortResolverImpl();

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerPort(8443);
		request.setScheme("HTtP"); // proves case insensitive handling
		assertThat(pr.getServerPort(request)).isEqualTo(8080);
	}

	@Test
	public void testDetectsBuggyIeHttpsRequest() {
		PortResolverImpl pr = new PortResolverImpl();

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerPort(8080);
		request.setScheme("HTtPs"); // proves case insensitive handling
		assertThat(pr.getServerPort(request)).isEqualTo(8443);
	}

	@Test
	public void testDetectsEmptyPortMapper() {
		PortResolverImpl pr = new PortResolverImpl();

		try {
			pr.setPortMapper(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testGettersSetters() {
		PortResolverImpl pr = new PortResolverImpl();
		assertThat(pr.getPortMapper() != null).isTrue();
		pr.setPortMapper(new PortMapperImpl());
		assertThat(pr.getPortMapper() != null).isTrue();
	}

	@Test
	public void testNormalOperation() {
		PortResolverImpl pr = new PortResolverImpl();

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("http");
		request.setServerPort(1021);
		assertThat(pr.getServerPort(request)).isEqualTo(1021);
	}

}
