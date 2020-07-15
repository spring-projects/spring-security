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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class Saml2WebSsoAuthenticationFilterTests {

	private Saml2WebSsoAuthenticationFilter filter;
	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private HttpServletResponse response = new MockHttpServletResponse();

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setup() {
		filter = new Saml2WebSsoAuthenticationFilter(repository);
		request.setPathInfo("/login/saml2/sso/idp-registration-id");
		request.setParameter("SAMLResponse", "xml-data-goes-here");
	}

	@Test
	public void constructingFilterWithMissingRegistrationIdVariableThenThrowsException() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("filterProcessesUrl must contain a {registrationId} match variable");
		filter = new Saml2WebSsoAuthenticationFilter(repository, "/url/missing/variable");
	}

	@Test
	public void constructingFilterWithValidRegistrationIdVariableThenSucceeds() {
		filter = new Saml2WebSsoAuthenticationFilter(repository, "/url/variable/is/present/{registrationId}");
	}

	@Test
	public void requiresAuthenticationWhenHappyPathThenReturnsTrue() {
		Assert.assertTrue(filter.requiresAuthentication(request, response));
	}

	@Test
	public void requiresAuthenticationWhenCustomProcessingUrlThenReturnsTrue() {
		filter = new Saml2WebSsoAuthenticationFilter(repository, "/some/other/path/{registrationId}");
		request.setPathInfo("/some/other/path/idp-registration-id");
		request.setParameter("SAMLResponse", "xml-data-goes-here");
		Assert.assertTrue(filter.requiresAuthentication(request, response));
	}

	@Test
	public void attemptAuthenticationWhenRegistrationIdDoesNotExistThenThrowsException() {
		when(repository.findByRegistrationId("non-existent-id")).thenReturn(null);

		filter = new Saml2WebSsoAuthenticationFilter(repository, "/some/other/path/{registrationId}");

		request.setPathInfo("/some/other/path/non-existent-id");
		request.setParameter("SAMLResponse", "response");

		try {
			filter.attemptAuthentication(request, response);
			failBecauseExceptionWasNotThrown(Saml2AuthenticationException.class);
		} catch (Exception e) {
			assertThat(e).isInstanceOf(Saml2AuthenticationException.class);
			assertThat(e.getMessage()).isEqualTo("Relying Party Registration not found with ID: non-existent-id");
		}
	}
}
