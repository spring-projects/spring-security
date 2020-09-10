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

package org.springframework.security.cas.web;

import java.net.URLEncoder;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.cas.ServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link CasAuthenticationEntryPoint}.
 *
 * @author Ben Alex
 */
public class CasAuthenticationEntryPointTests {

	@Test
	public void testDetectsMissingLoginFormUrl() throws Exception {
		CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
		ep.setServiceProperties(new ServiceProperties());
		assertThatIllegalArgumentException().isThrownBy(ep::afterPropertiesSet)
				.withMessage("loginUrl must be specified");
	}

	@Test
	public void testDetectsMissingServiceProperties() throws Exception {
		CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
		ep.setLoginUrl("https://cas/login");
		assertThatIllegalArgumentException().isThrownBy(ep::afterPropertiesSet)
				.withMessage("serviceProperties must be specified");
	}

	@Test
	public void testGettersSetters() {
		CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
		ep.setLoginUrl("https://cas/login");
		assertThat(ep.getLoginUrl()).isEqualTo("https://cas/login");
		ep.setServiceProperties(new ServiceProperties());
		assertThat(ep.getServiceProperties() != null).isTrue();
	}

	@Test
	public void testNormalOperationWithRenewFalse() throws Exception {
		ServiceProperties sp = new ServiceProperties();
		sp.setSendRenew(false);
		sp.setService("https://mycompany.com/bigWebApp/login/cas");
		CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
		ep.setLoginUrl("https://cas/login");
		ep.setServiceProperties(sp);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.afterPropertiesSet();
		ep.commence(request, response, null);
		assertThat(
				"https://cas/login?service=" + URLEncoder.encode("https://mycompany.com/bigWebApp/login/cas", "UTF-8"))
						.isEqualTo(response.getRedirectedUrl());
	}

	@Test
	public void testNormalOperationWithRenewTrue() throws Exception {
		ServiceProperties sp = new ServiceProperties();
		sp.setSendRenew(true);
		sp.setService("https://mycompany.com/bigWebApp/login/cas");
		CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
		ep.setLoginUrl("https://cas/login");
		ep.setServiceProperties(sp);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.afterPropertiesSet();
		ep.commence(request, response, null);
		assertThat("https://cas/login?service="
				+ URLEncoder.encode("https://mycompany.com/bigWebApp/login/cas", "UTF-8") + "&renew=true")
						.isEqualTo(response.getRedirectedUrl());
	}

}
