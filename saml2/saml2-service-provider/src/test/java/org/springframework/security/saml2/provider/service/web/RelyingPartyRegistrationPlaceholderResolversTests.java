/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link RelyingPartyRegistrationPlaceholderResolvers}
 */
public class RelyingPartyRegistrationPlaceholderResolversTests {

	@Test
	void uriResolverGivenRequestCreatesResolver() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request);
		String resolved = uriResolver.resolve("{baseUrl}/extension");
		assertThat(resolved).isEqualTo("http://localhost/extension");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> uriResolver.resolve("{baseUrl}/extension/{registrationId}"));
	}

	@Test
	void uriResolverGivenRequestAndRegistrationCreatesResolver() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
			.entityId("http://sp.example.org")
			.build();
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		String resolved = uriResolver.resolve("{baseUrl}/extension/{registrationId}");
		assertThat(resolved).isEqualTo("http://localhost/extension/simplesamlphp");
		resolved = uriResolver.resolve("{relyingPartyEntityId}/extension");
		assertThat(resolved).isEqualTo("http://sp.example.org/extension");
	}

}
