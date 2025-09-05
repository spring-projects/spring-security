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
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation used for OAuth 2.0 Client
 * Authentication, which authenticates the client {@code X509Certificate} received when
 * the {@code tls_client_auth} or {@code self_signed_tls_client_auth} authentication
 * method is used.
 *
 * @author Joe Grandja
 * @since 1.3
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 */
public final class X509ClientCertificateAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

	private final Log logger = LogFactory.getLog(getClass());

	private final RegisteredClientRepository registeredClientRepository;

	private final CodeVerifierAuthenticator codeVerifierAuthenticator;

	private final Consumer<OAuth2ClientAuthenticationContext> selfSignedCertificateVerifier = new X509SelfSignedCertificateVerifier();

	private Consumer<OAuth2ClientAuthenticationContext> certificateVerifier = this::verifyX509Certificate;

	/**
	 * Constructs a {@code X509ClientCertificateAuthenticationProvider} using the provided
	 * parameters.
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public X509ClientCertificateAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.codeVerifierAuthenticator = new CodeVerifierAuthenticator(authorizationService);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

		if (!ClientAuthenticationMethod.TLS_CLIENT_AUTH.equals(clientAuthentication.getClientAuthenticationMethod())
				&& !ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
					.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		if (!registeredClient.getClientAuthenticationMethods()
			.contains(clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient("authentication_method");
		}

		if (!(clientAuthentication.getCredentials() instanceof X509Certificate[])) {
			throwInvalidClient("credentials");
		}

		OAuth2ClientAuthenticationContext authenticationContext = OAuth2ClientAuthenticationContext
			.with(clientAuthentication)
			.registeredClient(registeredClient)
			.build();
		this.certificateVerifier.accept(authenticationContext);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client authentication parameters");
		}

		// Validate the "code_verifier" parameter for the confidential client, if
		// available
		this.codeVerifierAuthenticator.authenticateIfAvailable(clientAuthentication, registeredClient);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client X509Certificate");
		}

		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), clientAuthentication.getCredentials());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2ClientAuthenticationContext} and is responsible for verifying the
	 * client {@code X509Certificate} associated in the
	 * {@link OAuth2ClientAuthenticationToken}. The default implementation for the
	 * {@code tls_client_auth} authentication method verifies the
	 * {@link ClientSettings#getX509CertificateSubjectDN() expected subject distinguished
	 * name}.
	 *
	 * <p>
	 * <b>NOTE:</b> If verification fails, an {@link OAuth2AuthenticationException} MUST
	 * be thrown.
	 * @param certificateVerifier the {@code Consumer} providing access to the
	 * {@link OAuth2ClientAuthenticationContext} and is responsible for verifying the
	 * client {@code X509Certificate}
	 */
	public void setCertificateVerifier(Consumer<OAuth2ClientAuthenticationContext> certificateVerifier) {
		Assert.notNull(certificateVerifier, "certificateVerifier cannot be null");
		this.certificateVerifier = certificateVerifier;
	}

	private void verifyX509Certificate(OAuth2ClientAuthenticationContext clientAuthenticationContext) {
		OAuth2ClientAuthenticationToken clientAuthentication = clientAuthenticationContext.getAuthentication();
		if (ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
			.equals(clientAuthentication.getClientAuthenticationMethod())) {
			this.selfSignedCertificateVerifier.accept(clientAuthenticationContext);
		}
		else {
			verifyX509CertificateSubjectDN(clientAuthenticationContext);
		}
	}

	private void verifyX509CertificateSubjectDN(OAuth2ClientAuthenticationContext clientAuthenticationContext) {
		OAuth2ClientAuthenticationToken clientAuthentication = clientAuthenticationContext.getAuthentication();
		RegisteredClient registeredClient = clientAuthenticationContext.getRegisteredClient();
		X509Certificate[] clientCertificateChain = (X509Certificate[]) clientAuthentication.getCredentials();
		X509Certificate clientCertificate = clientCertificateChain[0];
		String expectedSubjectDN = registeredClient.getClientSettings().getX509CertificateSubjectDN();
		if (!StringUtils.hasText(expectedSubjectDN)
				|| !clientCertificate.getSubjectX500Principal().getName().equals(expectedSubjectDN)) {
			throwInvalidClient("x509_certificate_subject_dn");
		}
	}

	private static void throwInvalidClient(String parameterName) {
		throwInvalidClient(parameterName, null);
	}

	private static void throwInvalidClient(String parameterName, Throwable cause) {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
				"Client authentication failed: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error, error.toString(), cause);
	}

}
