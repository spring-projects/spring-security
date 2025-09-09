/*
 * Copyright 2004-present the original author or authors.
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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.security.auth.x500.X500Principal;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * The default {@code X509Certificate} verifier for the
 * {@code self_signed_tls_client_auth} authentication method.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see X509ClientCertificateAuthenticationProvider#setCertificateVerifier(Consumer)
 */
final class X509SelfSignedCertificateVerifier implements Consumer<OAuth2ClientAuthenticationContext> {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

	private static final JWKMatcher HAS_X509_CERT_CHAIN_MATCHER = new JWKMatcher.Builder().hasX509CertChain(true)
		.build();

	private final Function<RegisteredClient, JWKSet> jwkSetSupplier = new JwkSetSupplier();

	@Override
	public void accept(OAuth2ClientAuthenticationContext clientAuthenticationContext) {
		OAuth2ClientAuthenticationToken clientAuthentication = clientAuthenticationContext.getAuthentication();
		RegisteredClient registeredClient = clientAuthenticationContext.getRegisteredClient();
		X509Certificate[] clientCertificateChain = (X509Certificate[]) clientAuthentication.getCredentials();
		X509Certificate clientCertificate = clientCertificateChain[0];

		X500Principal issuer = clientCertificate.getIssuerX500Principal();
		X500Principal subject = clientCertificate.getSubjectX500Principal();
		if (issuer == null || !issuer.equals(subject)) {
			throwInvalidClient("x509_certificate_issuer");
		}

		JWKSet jwkSet = this.jwkSetSupplier.apply(registeredClient);

		boolean publicKeyMatches = false;
		for (JWK jwk : jwkSet.filter(HAS_X509_CERT_CHAIN_MATCHER).getKeys()) {
			X509Certificate x509Certificate = jwk.getParsedX509CertChain().get(0);
			PublicKey publicKey = x509Certificate.getPublicKey();
			if (Arrays.equals(clientCertificate.getPublicKey().getEncoded(), publicKey.getEncoded())) {
				publicKeyMatches = true;
				break;
			}
		}

		if (!publicKeyMatches) {
			throwInvalidClient("x509_certificate");
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

	private static final class JwkSetSupplier implements Function<RegisteredClient, JWKSet> {

		private static final MediaType APPLICATION_JWK_SET_JSON = new MediaType("application", "jwk-set+json");

		private final RestOperations restOperations;

		private final Map<String, Supplier<JWKSet>> jwkSets = new ConcurrentHashMap<>();

		private JwkSetSupplier() {
			SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
			requestFactory.setConnectTimeout(15_000);
			requestFactory.setReadTimeout(15_000);
			this.restOperations = new RestTemplate(requestFactory);
		}

		@Override
		public JWKSet apply(RegisteredClient registeredClient) {
			Supplier<JWKSet> jwkSetSupplier = this.jwkSets.computeIfAbsent(registeredClient.getId(), (key) -> {
				if (!StringUtils.hasText(registeredClient.getClientSettings().getJwkSetUrl())) {
					throwInvalidClient("client_jwk_set_url");
				}
				return new JwkSetHolder(registeredClient.getClientSettings().getJwkSetUrl());
			});
			return jwkSetSupplier.get();
		}

		private JWKSet retrieve(String jwkSetUrl) {
			URI jwkSetUri = null;
			try {
				jwkSetUri = new URI(jwkSetUrl);
			}
			catch (URISyntaxException ex) {
				throwInvalidClient("jwk_set_uri", ex);
			}

			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON));
			RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, jwkSetUri);
			ResponseEntity<String> response = null;
			try {
				response = this.restOperations.exchange(request, String.class);
			}
			catch (Exception ex) {
				throwInvalidClient("jwk_set_response_error", ex);
			}
			if (response.getStatusCode().value() != 200) {
				throwInvalidClient("jwk_set_response_status");
			}

			JWKSet jwkSet = null;
			try {
				jwkSet = JWKSet.parse(response.getBody());
			}
			catch (ParseException ex) {
				throwInvalidClient("jwk_set_response_body", ex);
			}

			return jwkSet;
		}

		private final class JwkSetHolder implements Supplier<JWKSet> {

			private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();

			private final Clock clock = Clock.systemUTC();

			private final String jwkSetUrl;

			private JWKSet jwkSet;

			private Instant lastUpdatedAt;

			private JwkSetHolder(String jwkSetUrl) {
				this.jwkSetUrl = jwkSetUrl;
			}

			@Override
			public JWKSet get() {
				this.rwLock.readLock().lock();
				if (shouldRefresh()) {
					this.rwLock.readLock().unlock();
					this.rwLock.writeLock().lock();
					try {
						if (shouldRefresh()) {
							this.jwkSet = retrieve(this.jwkSetUrl);
							this.lastUpdatedAt = Instant.now();
						}
						this.rwLock.readLock().lock();
					}
					finally {
						this.rwLock.writeLock().unlock();
					}
				}

				try {
					return this.jwkSet;
				}
				finally {
					this.rwLock.readLock().unlock();
				}
			}

			private boolean shouldRefresh() {
				// Refresh every 5 minutes
				return (this.jwkSet == null
						|| this.clock.instant().isAfter(this.lastUpdatedAt.plus(5, ChronoUnit.MINUTES)));
			}

		}

	}

}
