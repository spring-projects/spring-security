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

package org.springframework.security.web.access.channel;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockPortResolver;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.RedirectStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link RetryWithHttpEntryPoint}.
 *
 * @author Ben Alex
 */
public class RetryWithHttpEntryPointTests {
	// ~ Methods
	// ========================================================================================================
	@Test
	public void testDetectsMissingPortMapper() throws Exception {
		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();

		try {
			ep.setPortMapper(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void testDetectsMissingPortResolver() throws Exception {
		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();

		try {
			ep.setPortResolver(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void testGettersSetters() {
		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
		PortMapper portMapper = mock(PortMapper.class);
		PortResolver portResolver = mock(PortResolver.class);
		RedirectStrategy redirector = mock(RedirectStrategy.class);
		ep.setPortMapper(portMapper);
		ep.setPortResolver(portResolver);
		ep.setRedirectStrategy(redirector);
		assertThat(ep.getPortMapper()).isSameAs(portMapper);
		assertThat(ep.getPortResolver()).isSameAs(portResolver);
		assertThat(ep.getRedirectStrategy()).isSameAs(redirector);
	}

	@Test
	public void testNormalOperation() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET",
				"/bigWebApp/hello/pathInfo.html");
		request.setQueryString("open=true");
		request.setScheme("https");
		request.setServerName("localhost");
		request.setServerPort(443);

		MockHttpServletResponse response = new MockHttpServletResponse();

		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(80, 443));

		ep.commence(request, response);
		assertThat(response.getRedirectedUrl()).isEqualTo(
				"http://localhost/bigWebApp/hello/pathInfo.html?open=true");
	}

	@Test
	public void testNormalOperationWithNullQueryString() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET",
				"/bigWebApp/hello");
		request.setScheme("https");
		request.setServerName("localhost");
		request.setServerPort(443);

		MockHttpServletResponse response = new MockHttpServletResponse();

		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(80, 443));

		ep.commence(request, response);
		assertThat(response.getRedirectedUrl())
				.isEqualTo("http://localhost/bigWebApp/hello");
	}

	@Test
	public void testOperationWhenTargetPortIsUnknown() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp");
		request.setQueryString("open=true");
		request.setScheme("https");
		request.setServerName("www.example.com");
		request.setServerPort(8768);

		MockHttpServletResponse response = new MockHttpServletResponse();

		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(8768, 1234));

		ep.commence(request, response);
		assertThat(response.getRedirectedUrl()).isEqualTo("/bigWebApp?open=true");
	}

	@Test
	public void testOperationWithNonStandardPort() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET",
				"/bigWebApp/hello/pathInfo.html");
		request.setQueryString("open=true");
		request.setScheme("https");
		request.setServerName("localhost");
		request.setServerPort(9999);

		MockHttpServletResponse response = new MockHttpServletResponse();

		PortMapperImpl portMapper = new PortMapperImpl();
		Map<String, String> map = new HashMap<>();
		map.put("8888", "9999");
		portMapper.setPortMappings(map);

		RetryWithHttpEntryPoint ep = new RetryWithHttpEntryPoint();
		ep.setPortResolver(new MockPortResolver(8888, 9999));
		ep.setPortMapper(portMapper);

		ep.commence(request, response);
		assertThat(response.getRedirectedUrl()).isEqualTo(
				"http://localhost:8888/bigWebApp/hello/pathInfo.html?open=true");
	}
}
