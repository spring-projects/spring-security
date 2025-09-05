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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.util.TestX509Certificates;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link X509ClientCertificateAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class X509ClientCertificateAuthenticationProviderTests {

	// See RFC 7636: Appendix B. Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	private static final String AUTHORIZATION_CODE = "code";

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private JWKSet selfSignedCertificateJwkSet;

	private MockWebServer server;

	private String clientJwkSetUrl;

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private X509ClientCertificateAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() throws Exception {
		// @formatter:off
		X509Certificate selfSignedCertificate = TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE[0];
		RSAKey selfSignedRSAKey = new RSAKey.Builder((RSAPublicKey) selfSignedCertificate.getPublicKey())
				.keyUse(KeyUse.SIGNATURE)
				.keyID(UUID.randomUUID().toString())
				.x509CertChain(Collections.singletonList(Base64.encode(selfSignedCertificate.getEncoded())))
				.build();
		// @formatter:on
		this.selfSignedCertificateJwkSet = new JWKSet(selfSignedRSAKey);
		this.server = new MockWebServer();
		this.server.start();
		this.clientJwkSetUrl = this.server.url("/jwks").toString();
		// @formatter:off
		MockResponse response = new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(this.selfSignedCertificateJwkSet.toString());
		// @formatter:on
		this.server.enqueue(response);

		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new X509ClientCertificateAuthenticationProvider(this.registeredClientRepository,
				this.authorizationService);
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new X509ClientCertificateAuthenticationProvider(null, this.authorizationService))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new X509ClientCertificateAuthenticationProvider(this.registeredClientRepository, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void setCertificateVerifierWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setCertificateVerifier(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("certificateVerifier cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2ClientAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenInvalidClientIdThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId() + "-invalid", ClientAuthenticationMethod.TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains(OAuth2ParameterNames.CLIENT_ID);
			});
	}

	@Test
	public void authenticateWhenUnsupportedClientAuthenticationMethodThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains("authentication_method");
			});
	}

	@Test
	public void authenticateWhenX509CertificateNotProvidedThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.TLS_CLIENT_AUTH, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains("credentials");
			});
	}

	@Test
	public void authenticateWhenPKIX509CertificateInvalidSubjectDNThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.x509CertificateSubjectDN("CN=demo-client-sample-2,OU=Spring Samples,O=Spring,C=US")
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains("x509_certificate_subject_dn");
			});
	}

	@Test
	public void authenticateWhenPKIX509CertificateValidThenAuthenticated() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.x509CertificateSubjectDN(TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE[0].getSubjectX500Principal().getName())
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE, null);

		OAuth2ClientAuthenticationToken authenticationResult = (OAuth2ClientAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal().toString()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getCredentials()).isEqualTo(TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateInvalidIssuerThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl(this.clientJwkSetUrl)
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		// PKI Certificate will have different issuer
		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains("x509_certificate_issuer");
			});
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateMissingClientJwkSetUrlThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains("client_jwk_set_url");
			});
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateInvalidClientJwkSetUrlThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl("https://this is an invalid URL")
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains("jwk_set_uri");
			});
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateJwkSetResponseErrorStatusThenThrowOAuth2AuthenticationException() {
		MockResponse jwkSetResponse = new MockResponse().setResponseCode(400);
		authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidThenThrowOAuth2AuthenticationException(
				jwkSetResponse, "jwk_set_response_error");
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidStatusThenThrowOAuth2AuthenticationException() {
		MockResponse jwkSetResponse = new MockResponse().setResponseCode(204);
		authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidThenThrowOAuth2AuthenticationException(
				jwkSetResponse, "jwk_set_response_status");
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidContentThenThrowOAuth2AuthenticationException() {
		MockResponse jwkSetResponse = new MockResponse().setResponseCode(200).setBody("invalid-content");
		authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidThenThrowOAuth2AuthenticationException(
				jwkSetResponse, "jwk_set_response_body");
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateJwkSetResponseNoMatchingKeysThenThrowOAuth2AuthenticationException()
			throws Exception {
		// @formatter:off
		X509Certificate pkiCertificate = TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE[0];
		RSAKey pkiRSAKey = new RSAKey.Builder((RSAPublicKey) pkiCertificate.getPublicKey())
				.keyUse(KeyUse.SIGNATURE)
				.keyID(UUID.randomUUID().toString())
				.x509CertChain(Collections.singletonList(Base64.encode(pkiCertificate.getEncoded())))
				.build();
		// @formatter:on

		// @formatter:off
		MockResponse jwkSetResponse = new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(new JWKSet(pkiRSAKey).toString());
		// @formatter:on

		authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidThenThrowOAuth2AuthenticationException(
				jwkSetResponse, "x509_certificate");
	}

	private void authenticateWhenSelfSignedX509CertificateJwkSetResponseInvalidThenThrowOAuth2AuthenticationException(
			final MockResponse jwkSetResponse, String expectedErrorDescription) {

		// @formatter:off
		final Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return jwkSetResponse;
			}
		};
		this.server.setDispatcher(dispatcher);
		// @formatter:on

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl(this.clientJwkSetUrl)
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
				assertThat(error.getDescription()).contains(expectedErrorDescription);
			});
	}

	@Test
	public void authenticateWhenSelfSignedX509CertificateValidThenAuthenticated() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl(this.clientJwkSetUrl)
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE, null);

		OAuth2ClientAuthenticationToken authenticationResult = (OAuth2ClientAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal().toString()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getCredentials())
			.isEqualTo(TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
	}

	@Test
	public void authenticateWhenPkceAndValidCodeVerifierThenAuthenticated() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.x509CertificateSubjectDN(TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE[0].getSubjectX500Principal().getName())
								.build()
				)
				.build();
		// @formatter:on
		given(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
			.willReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, createPkceAuthorizationParametersS256())
			.build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		Map<String, Object> parameters = createPkceTokenParameters(S256_CODE_VERIFIER);

		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE, parameters);

		OAuth2ClientAuthenticationToken authenticationResult = (OAuth2ClientAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		verify(this.authorizationService).findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE));
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal().toString()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getCredentials()).isEqualTo(TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
	}

	private static Map<String, Object> createPkceAuthorizationParametersS256() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		parameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		return parameters;
	}

	private static Map<String, Object> createPkceTokenParameters(String codeVerifier) {
		Map<String, Object> parameters = createAuthorizationCodeTokenParameters();
		parameters.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		return parameters;
	}

	private static Map<String, Object> createAuthorizationCodeTokenParameters() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.put(OAuth2ParameterNames.CODE, AUTHORIZATION_CODE);
		return parameters;
	}

}
