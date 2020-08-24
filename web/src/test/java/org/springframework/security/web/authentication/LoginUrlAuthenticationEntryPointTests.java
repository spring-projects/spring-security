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

package org.springframework.security.web.authentication;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockPortResolver;
import org.springframework.security.web.PortMapperImpl;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link LoginUrlAuthenticationEntryPoint}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class LoginUrlAuthenticationEntryPointTests {

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsMissingLoginFormUrl() {
		new LoginUrlAuthenticationEntryPoint(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsMissingPortMapper() {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/login");
		ep.setPortMapper(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsMissingPortResolver() {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/login");
		ep.setPortResolver(null);
	}

	@Test
	public void testGettersSetters() {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(8080, 8443));
		assertThat(ep.getLoginFormUrl()).isEqualTo("/hello");
		assertThat(ep.getPortMapper() != null).isTrue();
		assertThat(ep.getPortResolver() != null).isTrue();
		ep.setForceHttps(false);
		assertThat(ep.isForceHttps()).isFalse();
		ep.setForceHttps(true);
		assertThat(ep.isForceHttps()).isTrue();
		assertThat(ep.isUseForward()).isFalse();
		ep.setUseForward(true);
		assertThat(ep.isUseForward()).isTrue();
	}

	@Test
	public void testHttpsOperationFromOriginalHttpUrl() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setContextPath("/bigWebApp");
		request.setServerPort(80);
		MockHttpServletResponse response = new MockHttpServletResponse();
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setPortMapper(new PortMapperImpl());
		ep.setForceHttps(true);
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(80, 443));
		ep.afterPropertiesSet();
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com/bigWebApp/hello");
		request.setServerPort(8080);
		response = new MockHttpServletResponse();
		ep.setPortResolver(new MockPortResolver(8080, 8443));
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com:8443/bigWebApp/hello");
		// Now test an unusual custom HTTP:HTTPS is handled properly
		request.setServerPort(8888);
		response = new MockHttpServletResponse();
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com:8443/bigWebApp/hello");
		PortMapperImpl portMapper = new PortMapperImpl();
		Map<String, String> map = new HashMap<>();
		map.put("8888", "9999");
		portMapper.setPortMappings(map);
		response = new MockHttpServletResponse();
		ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setPortMapper(new PortMapperImpl());
		ep.setForceHttps(true);
		ep.setPortMapper(portMapper);
		ep.setPortResolver(new MockPortResolver(8888, 9999));
		ep.afterPropertiesSet();
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com:9999/bigWebApp/hello");
	}

	@Test
	public void testHttpsOperationFromOriginalHttpsUrl() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		request.setScheme("https");
		request.setServerName("www.example.com");
		request.setContextPath("/bigWebApp");
		request.setServerPort(443);
		MockHttpServletResponse response = new MockHttpServletResponse();
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setPortMapper(new PortMapperImpl());
		ep.setForceHttps(true);
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(80, 443));
		ep.afterPropertiesSet();
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com/bigWebApp/hello");
		request.setServerPort(8443);
		response = new MockHttpServletResponse();
		ep.setPortResolver(new MockPortResolver(8080, 8443));
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com:8443/bigWebApp/hello");
	}

	@Test
	public void testNormalOperation() throws Exception {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setPortMapper(new PortMapperImpl());
		ep.setPortResolver(new MockPortResolver(80, 443));
		ep.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		request.setContextPath("/bigWebApp");
		request.setScheme("http");
		request.setServerName("localhost");
		request.setContextPath("/bigWebApp");
		request.setServerPort(80);
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/bigWebApp/hello");
	}

	@Test
	public void testOperationWhenHttpsRequestsButHttpsPortUnknown() throws Exception {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setPortResolver(new MockPortResolver(8888, 1234));
		ep.setForceHttps(true);
		ep.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		request.setContextPath("/bigWebApp");
		request.setScheme("http");
		request.setServerName("localhost");
		request.setContextPath("/bigWebApp");
		request.setServerPort(8888); // NB: Port we can't resolve
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.commence(request, response, null);
		// Response doesn't switch to HTTPS, as we didn't know HTTP port 8888 to HTTP port
		// mapping
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:8888/bigWebApp/hello");
	}

	@Test
	public void testServerSideRedirectWithoutForceHttpsForwardsToLoginPage() throws Exception {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setUseForward(true);
		ep.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/bigWebApp/some_path");
		request.setServletPath("/some_path");
		request.setContextPath("/bigWebApp");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setContextPath("/bigWebApp");
		request.setServerPort(80);
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.commence(request, response, null);
		assertThat(response.getForwardedUrl()).isEqualTo("/hello");
	}

	@Test
	public void testServerSideRedirectWithForceHttpsRedirectsCurrentRequest() throws Exception {
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("/hello");
		ep.setUseForward(true);
		ep.setForceHttps(true);
		ep.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/bigWebApp/some_path");
		request.setServletPath("/some_path");
		request.setContextPath("/bigWebApp");
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setContextPath("/bigWebApp");
		request.setServerPort(80);
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.commence(request, response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.example.com/bigWebApp/some_path");
	}

	// SEC-1498
	@Test
	public void absoluteLoginFormUrlIsSupported() throws Exception {
		final String loginFormUrl = "https://somesite.com/login";
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint(loginFormUrl);
		ep.afterPropertiesSet();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.commence(new MockHttpServletRequest("GET", "/someUrl"), response, null);
		assertThat(response.getRedirectedUrl()).isEqualTo(loginFormUrl);
	}

	@Test(expected = IllegalArgumentException.class)
	public void absoluteLoginFormUrlCantBeUsedWithForwarding() throws Exception {
		final String loginFormUrl = "https://somesite.com/login";
		LoginUrlAuthenticationEntryPoint ep = new LoginUrlAuthenticationEntryPoint("https://somesite.com/login");
		ep.setUseForward(true);
		ep.afterPropertiesSet();
	}

}
