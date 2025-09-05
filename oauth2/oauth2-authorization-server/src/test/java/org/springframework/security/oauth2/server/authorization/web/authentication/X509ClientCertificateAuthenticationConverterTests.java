/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.util.TestX509Certificates;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link X509ClientCertificateAuthenticationConverter}.
 *
 * @author Joe Grandja
 */
public class X509ClientCertificateAuthenticationConverterTests {

	private final X509ClientCertificateAuthenticationConverter converter = new X509ClientCertificateAuthenticationConverter();

	@Test
	public void convertWhenMissingX509CertificateThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenEmptyX509CertificateThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[0]);
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingClientIdThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate",
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate",
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2");
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenPkiX509CertificateThenReturnClientAuthenticationToken() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate",
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication.getPrincipal()).isEqualTo("client-1");
		assertThat(authentication.getCredentials()).isEqualTo(TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		assertThat(authentication.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
		assertThat(authentication.getAdditionalParameters()).containsOnly(
				entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				entry(OAuth2ParameterNames.CODE, "code"), entry("custom-param-1", "custom-value-1"),
				entry("custom-param-2", new String[] { "custom-value-1", "custom-value-2" }));
	}

	@Test
	public void convertWhenSelfSignedX509CertificateThenReturnClientAuthenticationToken() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate",
				TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication.getPrincipal()).isEqualTo("client-1");
		assertThat(authentication.getCredentials()).isEqualTo(TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE);
		assertThat(authentication.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
		assertThat(authentication.getAdditionalParameters()).containsOnly(
				entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				entry(OAuth2ParameterNames.CODE, "code"), entry("custom-param-1", "custom-value-1"),
				entry("custom-param-2", new String[] { "custom-value-1", "custom-value-2" }));
	}

}
