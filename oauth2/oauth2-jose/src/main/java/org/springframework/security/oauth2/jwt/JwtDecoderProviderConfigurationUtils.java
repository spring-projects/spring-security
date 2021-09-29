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

package org.springframework.security.oauth2.jwt;

import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Allows resolving configuration from an <a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID
 * Provider Configuration</a> or
 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server Metadata
 * Request</a> based on provided issuer and method invoked.
 *
 * @author Thomas Vitale
 * @author Rafiullah Hamedy
 * @since 5.2
 */
final class JwtDecoderProviderConfigurationUtils {

	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

	private static final RestTemplate rest = new RestTemplate();

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private JwtDecoderProviderConfigurationUtils() {
	}

	static Map<String, Object> getConfigurationForOidcIssuerLocation(String oidcIssuerLocation) {
		return getConfiguration(oidcIssuerLocation, oidc(URI.create(oidcIssuerLocation)));
	}

	static Map<String, Object> getConfigurationForIssuerLocation(String issuer) {
		URI uri = URI.create(issuer);
		return getConfiguration(issuer, oidc(uri), oidcRfc8414(uri), oauth(uri));
	}

	static void validateIssuer(Map<String, Object> configuration, String issuer) {
		String metadataIssuer = getMetadataIssuer(configuration);
		Assert.state(issuer.equals(metadataIssuer), () -> "The Issuer \"" + metadataIssuer
				+ "\" provided in the configuration did not " + "match the requested issuer \"" + issuer + "\"");
	}

	static <C extends SecurityContext> void addJWSAlgorithms(ConfigurableJWTProcessor<C> jwtProcessor) {
		JWSKeySelector<C> selector = jwtProcessor.getJWSKeySelector();
		if (selector instanceof JWSVerificationKeySelector) {
			JWKSource<C> jwkSource = ((JWSVerificationKeySelector<C>) selector).getJWKSource();
			Set<JWSAlgorithm> algorithms = getJWSAlgorithms(jwkSource);
			selector = new JWSVerificationKeySelector<>(algorithms, jwkSource);
			jwtProcessor.setJWSKeySelector(selector);
		}
	}

	static <C extends SecurityContext> Set<JWSAlgorithm> getJWSAlgorithms(JWKSource<C> jwkSource) {
		JWKMatcher jwkMatcher = new JWKMatcher.Builder().publicOnly(true).keyUses(KeyUse.SIGNATURE, null)
				.keyTypes(KeyType.RSA, KeyType.EC).build();
		Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
		try {
			List<? extends JWK> jwks = jwkSource.get(new JWKSelector(jwkMatcher), null);
			for (JWK jwk : jwks) {
				if (jwk.getAlgorithm() != null) {
					JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(jwk.getAlgorithm().getName());
					jwsAlgorithms.add(jwsAlgorithm);
				}
				else {
					if (jwk.getKeyType() == KeyType.RSA) {
						jwsAlgorithms.addAll(JWSAlgorithm.Family.RSA);
					}
					else if (jwk.getKeyType() == KeyType.EC) {
						jwsAlgorithms.addAll(JWSAlgorithm.Family.EC);
					}
				}
			}
		}
		catch (KeySourceException ex) {
			throw new IllegalStateException(ex);
		}
		Assert.notEmpty(jwsAlgorithms, "Failed to find any algorithms from the JWK set");
		return jwsAlgorithms;
	}

	static Set<SignatureAlgorithm> getSignatureAlgorithms(JWKSource<SecurityContext> jwkSource) {
		Set<JWSAlgorithm> jwsAlgorithms = getJWSAlgorithms(jwkSource);
		Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();
		for (JWSAlgorithm jwsAlgorithm : jwsAlgorithms) {
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(jwsAlgorithm.getName());
			if (signatureAlgorithm != null) {
				signatureAlgorithms.add(signatureAlgorithm);
			}
		}
		return signatureAlgorithms;
	}

	private static String getMetadataIssuer(Map<String, Object> configuration) {
		if (configuration.containsKey("issuer")) {
			return configuration.get("issuer").toString();
		}
		return "(unavailable)";
	}

	private static Map<String, Object> getConfiguration(String issuer, URI... uris) {
		String errorMessage = "Unable to resolve the Configuration with the provided Issuer of " + "\"" + issuer + "\"";
		for (URI uri : uris) {
			try {
				RequestEntity<Void> request = RequestEntity.get(uri).build();
				ResponseEntity<Map<String, Object>> response = rest.exchange(request, STRING_OBJECT_MAP);
				Map<String, Object> configuration = response.getBody();
				Assert.isTrue(configuration.get("jwks_uri") != null, "The public JWK set URI must not be null");
				return configuration;
			}
			catch (IllegalArgumentException ex) {
				throw ex;
			}
			catch (RuntimeException ex) {
				if (!(ex instanceof HttpClientErrorException
						&& ((HttpClientErrorException) ex).getStatusCode().is4xxClientError())) {
					throw new IllegalArgumentException(errorMessage, ex);
				}
				// else try another endpoint
			}
		}
		throw new IllegalArgumentException(errorMessage);
	}

	private static URI oidc(URI issuer) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(issuer.getPath() + OIDC_METADATA_PATH)
				.build(Collections.emptyMap());
		// @formatter:on
	}

	private static URI oidcRfc8414(URI issuer) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(OIDC_METADATA_PATH + issuer.getPath())
				.build(Collections.emptyMap());
		// @formatter:on
	}

	private static URI oauth(URI issuer) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(OAUTH_METADATA_PATH + issuer.getPath())
				.build(Collections.emptyMap());
		// @formatter:on
	}

}
