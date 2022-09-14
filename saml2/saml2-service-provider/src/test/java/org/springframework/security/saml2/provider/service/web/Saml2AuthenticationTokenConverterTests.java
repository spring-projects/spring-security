/*
 * Copyright 2002-2021 the original author or authors.
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2Utils;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.util.StreamUtils;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class Saml2AuthenticationTokenConverterTests {

	@Mock
	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.relyingPartyRegistration()
			.build();

	@Test
	public void convertWhenSamlResponseThenToken() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE,
				Saml2Utils.samlEncode("response".getBytes(StandardCharsets.UTF_8)));
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
	}

	@Test
	public void convertWhenSamlResponseWithRelyingPartyRegistrationResolver(
			@Mock RelyingPartyRegistrationResolver resolver) {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(resolver);
		given(resolver.resolve(any(HttpServletRequest.class), any())).willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE,
				Saml2Utils.samlEncode("response".getBytes(StandardCharsets.UTF_8)));
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
		verify(resolver).resolve(any(), isNull());
	}

	@Test
	public void convertWhenSamlResponseInvalidBase64ThenSaml2AuthenticationException() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "invalid");
		assertThatExceptionOfType(Saml2AuthenticationException.class).isThrownBy(() -> converter.convert(request))
				.withCauseInstanceOf(IllegalArgumentException.class)
				.satisfies((ex) -> assertThat(ex.getSaml2Error().getErrorCode())
						.isEqualTo(Saml2ErrorCodes.INVALID_RESPONSE))
				.satisfies((ex) -> assertThat(ex.getSaml2Error().getDescription())
						.isEqualTo("Failed to decode SAMLResponse"));
	}

	@Test
	public void convertWhenNoSamlResponseThenNull() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenNoRelyingPartyRegistrationThenNull() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any())).willReturn(null);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenGetRequestThenInflates() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		byte[] deflated = Saml2Utils.samlDeflate("response");
		String encoded = Saml2Utils.samlEncode(deflated);
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, encoded);
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
	}

	@Test
	public void convertWhenGetRequestInvalidDeflatedThenSaml2AuthenticationException() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		byte[] invalidDeflated = "invalid".getBytes();
		String encoded = Saml2Utils.samlEncode(invalidDeflated);
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, encoded);
		assertThatExceptionOfType(Saml2AuthenticationException.class).isThrownBy(() -> converter.convert(request))
				.withCauseInstanceOf(IOException.class)
				.satisfies((ex) -> assertThat(ex.getSaml2Error().getErrorCode())
						.isEqualTo(Saml2ErrorCodes.INVALID_RESPONSE))
				.satisfies(
						(ex) -> assertThat(ex.getSaml2Error().getDescription()).isEqualTo("Unable to inflate string"));
	}

	@Test
	public void convertWhenUsingSamlUtilsBase64ThenXmlIsValid() throws Exception {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, getSsoCircleEncodedXml());
		Saml2AuthenticationToken token = converter.convert(request);
		validateSsoCircleXml(token.getSaml2Response());
	}

	@Test
	public void convertWhenSavedAuthenticationRequestThenToken() {
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		AbstractSaml2AuthenticationRequest authenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		given(authenticationRequest.getRelyingPartyRegistrationId())
				.willReturn(this.relyingPartyRegistration.getRegistrationId());
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		converter.setAuthenticationRequestRepository(authenticationRequestRepository);
		given(this.relyingPartyRegistrationResolver.resolve(any(HttpServletRequest.class), any()))
				.willReturn(this.relyingPartyRegistration);
		given(authenticationRequestRepository.loadAuthenticationRequest(any(HttpServletRequest.class)))
				.willReturn(authenticationRequest);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE,
				Saml2Utils.samlEncode("response".getBytes(StandardCharsets.UTF_8)));
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
		assertThat(token.getAuthenticationRequest()).isEqualTo(authenticationRequest);
	}

	@Test
	public void convertWhenSavedAuthenticationRequestThenTokenWithRelyingPartyRegistrationResolver(
			@Mock RelyingPartyRegistrationResolver resolver) {
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		AbstractSaml2AuthenticationRequest authenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		given(authenticationRequest.getRelyingPartyRegistrationId())
				.willReturn(this.relyingPartyRegistration.getRegistrationId());
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(resolver);
		converter.setAuthenticationRequestRepository(authenticationRequestRepository);
		given(resolver.resolve(any(HttpServletRequest.class), any())).willReturn(this.relyingPartyRegistration);
		given(authenticationRequestRepository.loadAuthenticationRequest(any(HttpServletRequest.class)))
				.willReturn(authenticationRequest);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE,
				Saml2Utils.samlEncode("response".getBytes(StandardCharsets.UTF_8)));
		Saml2AuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2Response()).isEqualTo("response");
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
		assertThat(token.getAuthenticationRequest()).isEqualTo(authenticationRequest);
		verify(resolver).resolve(any(), eq(this.relyingPartyRegistration.getRegistrationId()));
	}

	@Test
	public void constructorWhenResolverIsNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> new Saml2AuthenticationTokenConverter(null));
	}

	@Test
	public void setAuthenticationRequestRepositoryWhenNullThenIllegalArgument() {
		Saml2AuthenticationTokenConverter converter = new Saml2AuthenticationTokenConverter(
				this.relyingPartyRegistrationResolver);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> converter.setAuthenticationRequestRepository(null));
	}

	private void validateSsoCircleXml(String xml) {
		assertThat(xml).contains("InResponseTo=\"ARQ9a73ead-7dcf-45a8-89eb-26f3c9900c36\"")
				.contains(" ID=\"s246d157446618e90e43fb79bdd4d9e9e19cf2c7c4\"")
				.contains("<saml:Issuer>https://idp.ssocircle.com</saml:Issuer>");
	}

	private String getSsoCircleEncodedXml() throws IOException {
		ClassPathResource resource = new ClassPathResource("saml2-response-sso-circle.encoded");
		String response = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
		return UriUtils.decode(response, StandardCharsets.UTF_8);
	}

}
