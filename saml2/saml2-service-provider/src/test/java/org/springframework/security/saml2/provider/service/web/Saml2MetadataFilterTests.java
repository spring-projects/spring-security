/*
 * Copyright 2002-2024 the original author or authors.
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponse;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link Saml2MetadataFilter}
 */
public class Saml2MetadataFilterTests {

	RelyingPartyRegistrationRepository repository;

	Saml2MetadataResolver resolver;

	Saml2MetadataFilter filter;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	FilterChain chain;

	@BeforeEach
	public void setup() {
		this.repository = mock(RelyingPartyRegistrationRepository.class);
		this.resolver = mock(Saml2MetadataResolver.class);
		this.filter = new Saml2MetadataFilter(this.repository, this.resolver);
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.chain = mock(FilterChain.class);
	}

	@Test
	public void doFilterWhenMatcherSucceedsThenResolverInvoked() throws Exception {
		this.request.setPathInfo("/saml2/service-provider-metadata/registration-id");
		this.filter.doFilter(this.request, this.response, this.chain);
		verifyNoInteractions(this.chain);
		verify(this.repository).findByRegistrationId("registration-id");
	}

	@Test
	public void doFilterWhenMatcherFailsThenProcessesFilterChain() throws Exception {
		this.request.setPathInfo("/saml2/authenticate/registration-id");
		this.filter.doFilter(this.request, this.response, this.chain);
		verify(this.chain).doFilter(this.request, this.response);
	}

	@Test
	public void doFilterWhenNoRelyingPartyRegistrationThenUnauthorized() throws Exception {
		this.request.setPathInfo("/saml2/service-provider-metadata/invalidRegistration");
		given(this.repository.findByRegistrationId("invalidRegistration")).willReturn(null);
		this.filter.doFilter(this.request, this.response, this.chain);
		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

	@Test
	public void doFilterWhenRelyingPartyRegistrationFoundThenInvokesMetadataResolver() throws Exception {
		this.request.setPathInfo("/saml2/service-provider-metadata/validRegistration");
		RelyingPartyRegistration validRegistration = TestRelyingPartyRegistrations.noCredentials()
			.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
			.build();
		String generatedMetadata = "<xml>test</xml>";
		given(this.resolver.resolve(validRegistration)).willReturn(generatedMetadata);
		this.filter = new Saml2MetadataFilter((request, registrationId) -> validRegistration, this.resolver);
		this.filter.doFilter(this.request, this.response, this.chain);
		verifyNoInteractions(this.chain);
		assertThat(this.response.getStatus()).isEqualTo(200);
		assertThat(this.response.getContentAsString()).isEqualTo(generatedMetadata);
		verify(this.resolver).resolve(validRegistration);
	}

	@Test
	public void doFilterWhenMatchesThenRespondsWithMetadata() throws Exception {
		Saml2MetadataResponse metadata = new Saml2MetadataResponse("<xml/>", "metadata.xml");
		Saml2MetadataResponseResolver resolver = mock(Saml2MetadataResponseResolver.class);
		given(resolver.resolve(this.request)).willReturn(metadata);
		Saml2MetadataFilter filter = new Saml2MetadataFilter(resolver);
		filter.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getContentType()).isEqualTo("application/samlmetadata+xml;charset=UTF-8");
		assertThat(this.response.getContentAsString()).isEqualTo("<xml/>");
		assertThat(this.response.getHeaderValue(HttpHeaders.CONTENT_DISPOSITION)).asString()
			.isEqualTo("attachment; filename=\"metadata.xml\"; filename*=UTF-8''metadata.xml");
	}

	@Test
	public void doFilterWhenCustomRequestMatcherThenUses() throws Exception {
		this.request.setPathInfo("/path");
		this.filter.setRequestMatcher(new AntPathRequestMatcher("/path"));
		this.filter.doFilter(this.request, this.response, this.chain);
		verifyNoInteractions(this.chain);
		verify(this.repository).findByRegistrationId("path");
	}

	@Test
	public void doFilterWhenSetMetadataFilenameThenUses() throws Exception {
		RelyingPartyRegistration validRegistration = TestRelyingPartyRegistrations.full().build();
		String testMetadataFilename = "test-{registrationId}-metadata.xml";
		String fileName = testMetadataFilename.replace("{registrationId}", validRegistration.getRegistrationId());
		String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8.name());
		String generatedMetadata = "<xml>test</xml>";
		this.request.setPathInfo("/saml2/service-provider-metadata/registration-id");
		given(this.resolver.resolve(validRegistration)).willReturn(generatedMetadata);
		this.filter = new Saml2MetadataFilter((request, registrationId) -> validRegistration, this.resolver);
		this.filter.setMetadataFilename(testMetadataFilename);
		this.filter.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getHeaderValue(HttpHeaders.CONTENT_DISPOSITION)).asString()
			.isEqualTo("attachment; filename=\"%s\"; filename*=UTF-8''%s", fileName, encodedFileName);
	}

	@Test
	public void doFilterWhenResolverConstructorAndPathStartsWithRegistrationIdThenServesMetadata() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.repository.findByRegistrationId("registration-id")).willReturn(registration);
		given(this.resolver.resolve(any(RelyingPartyRegistration.class))).willReturn("metadata");
		RelyingPartyRegistrationResolver resolver = new DefaultRelyingPartyRegistrationResolver(
				(id) -> this.repository.findByRegistrationId("registration-id"));
		this.filter = new Saml2MetadataFilter(resolver, this.resolver);
		this.filter.setRequestMatcher(new AntPathRequestMatcher("/metadata"));
		this.request.setPathInfo("/metadata");
		this.filter.doFilter(this.request, this.response, new MockFilterChain());
		verify(this.repository).findByRegistrationId("registration-id");
	}

	@Test
	public void doFilterWhenRelyingPartyRegistrationRepositoryConstructorAndPathStartsWithRegistrationIdThenServesMetadata()
			throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.repository.findByRegistrationId("registration-id")).willReturn(registration);
		given(this.resolver.resolve(any(RelyingPartyRegistration.class))).willReturn("metadata");
		this.filter = new Saml2MetadataFilter((id) -> this.repository.findByRegistrationId("registration-id"),
				this.resolver);
		this.filter.setRequestMatcher(new AntPathRequestMatcher("/metadata"));
		this.request.setPathInfo("/metadata");
		this.filter.doFilter(this.request, this.response, new MockFilterChain());
		verify(this.repository).findByRegistrationId("registration-id");
	}

	// gh-12026
	@Test
	public void doFilterWhenCharacterEncodingThenEncodeSpecialCharactersCorrectly() throws Exception {
		RelyingPartyRegistration validRegistration = TestRelyingPartyRegistrations.full().build();
		String testMetadataFilename = "test-{registrationId}-metadata.xml";
		String generatedMetadata = "<xml>testäöü</xml>";
		this.request.setPathInfo("/saml2/service-provider-metadata/registration-id");
		given(this.resolver.resolve(validRegistration)).willReturn(generatedMetadata);
		this.filter = new Saml2MetadataFilter((req, id) -> validRegistration, this.resolver);
		this.filter.setMetadataFilename(testMetadataFilename);
		this.filter.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getCharacterEncoding()).isEqualTo(StandardCharsets.UTF_8.name());
		assertThat(this.response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo(generatedMetadata);
		assertThat(this.response.getContentLength())
			.isEqualTo(generatedMetadata.getBytes(StandardCharsets.UTF_8).length);
	}

	@Test
	public void setRequestMatcherWhenNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequestMatcher(null));
	}

	@Test
	public void setMetadataFilenameWhenEmptyThenThrowsException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> this.filter.setMetadataFilename(" "))
			.withMessage("metadataFilename cannot be empty");
	}

	@Test
	public void setMetadataFilenameWhenMissingRegistrationIdVariableThenThrowsException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setMetadataFilename("metadata-filename.xml"))
			.withMessage("metadataFilename must contain a {registrationId} match variable");
	}

	@Test
	public void constructorWhenRelyingPartyRegistrationRepositoryThenUses() throws Exception {
		RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
		this.filter = new Saml2MetadataFilter(repository, this.resolver);
		this.request.setPathInfo("/saml2/service-provider-metadata/one");
		this.filter.doFilter(this.request, this.response, this.chain);
		verify(repository).findByRegistrationId("one");
	}

}
