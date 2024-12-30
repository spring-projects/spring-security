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

import java.io.IOException;
import java.net.URLEncoder;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.web.RedirectStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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

	@Test
	void setRedirectStrategyThenUses() throws IOException {
		CasAuthenticationEntryPoint ep = new CasAuthenticationEntryPoint();
		ServiceProperties sp = new ServiceProperties();

		sp.setService("https://mycompany.com/login/cas");
		ep.setServiceProperties(sp);
		ep.setLoginUrl("https://cas/login");

		RedirectStrategy redirectStrategy = mock();

		ep.setRedirectStrategy(redirectStrategy);
		MockHttpServletRequest req = new MockHttpServletRequest();
		MockHttpServletResponse res = new MockHttpServletResponse();

		ep.commence(req, res, new BadCredentialsException("bad credentials"));

		verify(redirectStrategy).sendRedirect(eq(req), eq(res),
				eq("https://cas/login?service=https%3A%2F%2Fmycompany.com%2Flogin%2Fcas"));
	}

}
