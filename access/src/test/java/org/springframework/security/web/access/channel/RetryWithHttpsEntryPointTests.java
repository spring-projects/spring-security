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

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.PortMapperImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link RetryWithHttpsEntryPoint}.
 *
 * @author Ben Alex
 */
public class RetryWithHttpsEntryPointTests {

	@Test
	public void testDetectsMissingPortMapper() {
		RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
		assertThatIllegalArgumentException().isThrownBy(() -> ep.setPortMapper(null));
	}

	@Test
	public void testGettersSetters() {
		RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		assertThat(ep.getPortMapper() != null).isTrue();
	}

	@Test
	public void testNormalOperation() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello/pathInfo.html");
		request.setQueryString("open=true");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setServerPort(80);
		MockHttpServletResponse response = new MockHttpServletResponse();
		RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		ep.commence(request, response);
		assertThat(response.getRedirectedUrl())
			.isEqualTo("https://www.example.com/bigWebApp/hello/pathInfo.html?open=true");
	}

	@Test
	public void testNormalOperationWithNullQueryString() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setServerPort(80);
		MockHttpServletResponse response = new MockHttpServletResponse();
		RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		ep.commence(request, response);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com/bigWebApp/hello");
	}

	@Test
	public void testOperationWhenTargetPortIsUnknown() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp");
		request.setQueryString("open=true");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setServerPort(8768);
		MockHttpServletResponse response = new MockHttpServletResponse();
		RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
		ep.setPortMapper(new PortMapperImpl());
		ep.commence(request, response);
		assertThat(response.getRedirectedUrl()).isEqualTo("/bigWebApp?open=true");
	}

	@Test
	public void testOperationWithNonStandardPort() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/bigWebApp/hello/pathInfo.html");
		request.setQueryString("open=true");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setServerPort(8888);
		MockHttpServletResponse response = new MockHttpServletResponse();
		PortMapperImpl portMapper = new PortMapperImpl();
		Map<String, String> map = new HashMap<>();
		map.put("8888", "9999");
		portMapper.setPortMappings(map);
		RetryWithHttpsEntryPoint ep = new RetryWithHttpsEntryPoint();
		ep.setPortMapper(portMapper);
		ep.commence(request, response);
		assertThat(response.getRedirectedUrl())
			.isEqualTo("https://www.example.com:9999/bigWebApp/hello/pathInfo.html?open=true");
	}

}
