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

package org.springframework.security.saml2.provider.service.metadata;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public final class RequestMatcherMetadataResponseResolverTests {

	@Mock
	Saml2MetadataResolver metadataFactory;

	@Test
	void saml2MetadataRegistrationIdResolveWhenMatchesThenResolves() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		RelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(registration);
		RequestMatcherMetadataResponseResolver resolver = new RequestMatcherMetadataResponseResolver(registrations,
				this.metadataFactory);
		String registrationId = registration.getRegistrationId();
		given(this.metadataFactory.resolve(any(Collection.class))).willReturn("metadata");
		MockHttpServletRequest request = get("/saml2/metadata/" + registrationId);
		Saml2MetadataResponse response = resolver.resolve(request);
		assertThat(response.getMetadata()).isEqualTo("metadata");
		assertThat(response.getFileName()).isEqualTo("saml-" + registrationId + "-metadata.xml");
		verify(this.metadataFactory).resolve(any(Collection.class));
	}

	@Test
	void saml2MetadataResolveWhenNoMatchingRegistrationThenNull() {
		RelyingPartyRegistrationRepository registrations = mock(RelyingPartyRegistrationRepository.class);
		RequestMatcherMetadataResponseResolver resolver = new RequestMatcherMetadataResponseResolver(registrations,
				this.metadataFactory);
		MockHttpServletRequest request = get("/saml2/metadata");
		Saml2MetadataResponse response = resolver.resolve(request);
		assertThat(response).isNull();
	}

	@Test
	void saml2MetadataRegistrationIdResolveWhenNoMatchingRegistrationThenException() {
		RelyingPartyRegistrationRepository registrations = mock(RelyingPartyRegistrationRepository.class);
		RequestMatcherMetadataResponseResolver resolver = new RequestMatcherMetadataResponseResolver(registrations,
				this.metadataFactory);
		MockHttpServletRequest request = get("/saml2/metadata/id");
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> resolver.resolve(request));
	}

	@Test
	void resolveWhenNoRegistrationIdThenResolvesAll() {
		RelyingPartyRegistration one = withEntityId("one");
		RelyingPartyRegistration two = withEntityId("two");
		RelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(one, two);
		RequestMatcherMetadataResponseResolver resolver = new RequestMatcherMetadataResponseResolver(registrations,
				this.metadataFactory);
		given(this.metadataFactory.resolve(any(Collection.class))).willReturn("metadata");
		MockHttpServletRequest request = get("/saml2/metadata");
		Saml2MetadataResponse response = resolver.resolve(request);
		assertThat(response.getMetadata()).isEqualTo("metadata");
		assertThat(response.getFileName()).doesNotContain(one.getRegistrationId())
			.contains("saml")
			.contains("metadata.xml");
		verify(this.metadataFactory).resolve(any(Collection.class));
	}

	@Test
	void resolveWhenRequestDoesNotMatchThenNull() {
		RelyingPartyRegistrationRepository registrations = mock(RelyingPartyRegistrationRepository.class);
		RequestMatcherMetadataResponseResolver resolver = new RequestMatcherMetadataResponseResolver(registrations,
				this.metadataFactory);
		assertThat(resolver.resolve(new MockHttpServletRequest())).isNull();
	}

	// gh-13700
	@Test
	void resolveWhenNoRegistrationIdThenResolvesEntityIds() {
		RelyingPartyRegistration one = withEntityId("one");
		RelyingPartyRegistration two = withEntityId("two");
		RelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(one, two);
		RequestMatcherMetadataResponseResolver resolver = new RequestMatcherMetadataResponseResolver(registrations,
				this.metadataFactory);
		given(this.metadataFactory.resolve(any(Collection.class))).willReturn("metadata");
		resolver.resolve(get("/saml2/metadata"));
		ArgumentCaptor<Collection<RelyingPartyRegistration>> captor = ArgumentCaptor.forClass(Collection.class);
		verify(this.metadataFactory).resolve(captor.capture());
		Collection<RelyingPartyRegistration> resolved = captor.getValue();
		assertThat(resolved).hasSize(2);
		assertThat(resolved.iterator().next().getEntityId()).isEqualTo("one");
	}

	private MockHttpServletRequest get(String uri) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
		request.setServletPath(uri);
		return request;
	}

	private RelyingPartyRegistration withEntityId(String entityId) {
		return TestRelyingPartyRegistrations.relyingPartyRegistration()
			.registrationId(entityId)
			.entityId("{registrationId}")
			.build();
	}

}
