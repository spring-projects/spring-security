/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.util.ArrayList;
import java.util.HashMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.post;

/**
 * Tests for {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler}
 *
 * @author Josh Cummings
 */
public class Saml2RelyingPartyInitiatedLogoutSuccessHandlerTests {

	Saml2LogoutRequestResolver logoutRequestResolver = mock(Saml2LogoutRequestResolver.class);

	Saml2LogoutRequestRepository logoutRequestRepository = mock(Saml2LogoutRequestRepository.class);

	Saml2RelyingPartyInitiatedLogoutSuccessHandler logoutRequestSuccessHandler = new Saml2RelyingPartyInitiatedLogoutSuccessHandler(
			this.logoutRequestResolver);

	@BeforeEach
	public void setUp() {
		this.logoutRequestSuccessHandler.setLogoutRequestRepository(this.logoutRequestRepository);
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void onLogoutSuccessWhenRedirectThenRedirectsToAssertingParty() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
			.samlRequest("request")
			.build();
		MockHttpServletRequest request = post("/saml2/logout").build();
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		String content = response.getHeader("Location");
		assertThat(content).contains(Saml2ParameterNames.SAML_REQUEST);
		assertThat(content).startsWith(registration.getAssertingPartyMetadata().getSingleLogoutServiceLocation());
	}

	@Test
	public void onLogoutSuccessWhenPostThenPostsToAssertingParty() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
			.assertingPartyMetadata((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST))
			.build();
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
			.samlRequest("request")
			.build();
		MockHttpServletRequest request = post("/saml2/logout").build();
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		String content = response.getContentAsString();
		assertThat(content).contains(Saml2ParameterNames.SAML_REQUEST);
		assertThat(content).contains(registration.getAssertingPartyMetadata().getSingleLogoutServiceLocation());
		assertThat(content).contains(
				"<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'sha256-oZhLbc2kO8b8oaYLrUc7uye1MgVKMyLtPqWR4WtKF+c='\">");
		assertThat(content).contains("<script>window.onload = function() { document.forms[0].submit(); }</script>");
	}

	private Saml2Authentication authentication(RelyingPartyRegistration registration) {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>());
		principal.setRelyingPartyRegistrationId(registration.getRegistrationId());
		return new Saml2Authentication(principal, "response", new ArrayList<>());
	}

}
