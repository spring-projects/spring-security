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

package org.springframework.security.saml2.provider.service.web;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import javax.servlet.FilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class Saml2MetadataFilterTest {

	RelyingPartyRegistrationRepository repository;
	Saml2MetadataResolver saml2MetadataResolver;
	Saml2MetadataFilter filter;
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	FilterChain filterChain;

	@Before
	public void setup() {
		repository = mock(RelyingPartyRegistrationRepository.class);
		saml2MetadataResolver = mock(Saml2MetadataResolver.class);
		filter = new Saml2MetadataFilter(repository, saml2MetadataResolver);
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		filterChain = mock(FilterChain.class);
	}

	@Test
	public void shouldReturnValueWhenMatcherSucceed() throws Exception {
		// given
		request.setPathInfo("/saml2/service-provider-metadata/registration-id");

		// when
		filter.doFilter(request, response, filterChain);

		// then
		verifyNoInteractions(filterChain);
	}

	@Test
	public void shouldProcessFilterChainIfMatcherFails() throws Exception {
		// given
		request.setPathInfo("/saml2/authenticate/registration-id");

		// when
		filter.doFilter(request, response, filterChain);

		// then
		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void shouldReturn401IfNoRegistrationIsFound() throws Exception {
		// given
		request.setPathInfo("/saml2/service-provider-metadata/invalidRegistration");
		when(repository.findByRegistrationId("invalidRegistration")).thenReturn(null);

		// when
		filter.doFilter(request, response, filterChain);

		// then
		verifyNoInteractions(filterChain);
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void shouldInvokeMetadataGenerationIfRegistrationIsFound() throws Exception {
		// given
		request.setPathInfo("/saml2/service-provider-metadata/validRegistration");
		RelyingPartyRegistration validRegistration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		when(repository.findByRegistrationId("validRegistration")).thenReturn(validRegistration);

		String generatedMetadata = "<xml>test</xml>";
		when(saml2MetadataResolver.resolveMetadata(request, validRegistration)).thenReturn(generatedMetadata);

		filter = new Saml2MetadataFilter(repository, saml2MetadataResolver);

		// when
		filter.doFilter(request, response, filterChain);

		// then
		verifyNoInteractions(filterChain);
		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(response.getContentAsString()).isEqualTo(generatedMetadata);
		verify(saml2MetadataResolver).resolveMetadata(request, validRegistration);
	}

}
