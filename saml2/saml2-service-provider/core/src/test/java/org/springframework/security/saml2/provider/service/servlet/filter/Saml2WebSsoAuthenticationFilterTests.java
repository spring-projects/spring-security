/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.servlet.filter;

import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class Saml2WebSsoAuthenticationFilterTests {

	private Saml2WebSsoAuthenticationFilter filter;

	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private HttpServletResponse response = new MockHttpServletResponse();

	private AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

	@Before
	public void setup() {
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository);
		this.request.setPathInfo("/login/saml2/sso/idp-registration-id");
		this.request.setParameter("SAMLResponse", "xml-data-goes-here");
	}

	@Test
	public void constructingFilterWithMissingRegistrationIdVariableThenThrowsException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/url/missing/variable"))
				.withMessage("filterProcessesUrl must contain a {registrationId} match variable");
	}

	@Test
	public void constructingFilterWithValidRegistrationIdVariableThenSucceeds() {
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/url/variable/is/present/{registrationId}");
	}

	@Test
	public void requiresAuthenticationWhenHappyPathThenReturnsTrue() {
		Assert.assertTrue(this.filter.requiresAuthentication(this.request, this.response));
	}

	@Test
	public void requiresAuthenticationWhenCustomProcessingUrlThenReturnsTrue() {
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter("SAMLResponse", "xml-data-goes-here");
		Assert.assertTrue(this.filter.requiresAuthentication(this.request, this.response));
	}

	@Test
	public void attemptAuthenticationWhenRegistrationIdDoesNotExistThenThrowsException() {
		given(this.repository.findByRegistrationId("non-existent-id")).willReturn(null);
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/non-existent-id");
		this.request.setParameter("SAMLResponse", "response");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.filter.attemptAuthentication(this.request, this.response))
				.withMessage("No relying party registration found");
	}

	@Test
	public void doFilterWhenPathStartsWithRegistrationIdThenAuthenticates() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		given(this.repository.findByRegistrationId("registration-id")).willReturn(registration);
		given(this.authenticationManager.authenticate(authentication)).willReturn(authentication);
		String loginProcessingUrl = "/{registrationId}/login/saml2/sso";
		RequestMatcher matcher = new AntPathRequestMatcher(loginProcessingUrl);
		DefaultRelyingPartyRegistrationResolver delegate = new DefaultRelyingPartyRegistrationResolver(this.repository);
		RelyingPartyRegistrationResolver resolver = (request, id) -> {
			String registrationId = matcher.matcher(request).getVariables().get("registrationId");
			return delegate.resolve(request, registrationId);
		};
		Saml2AuthenticationTokenConverter authenticationConverter = new Saml2AuthenticationTokenConverter(resolver);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, loginProcessingUrl);
		this.filter.setAuthenticationManager(this.authenticationManager);
		this.request.setPathInfo("/registration-id/login/saml2/sso");
		this.request.setParameter("SAMLResponse", "response");
		this.filter.doFilter(this.request, this.response, new MockFilterChain());
		verify(this.repository).findByRegistrationId("registration-id");
	}

}
