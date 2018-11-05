/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.jwt;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * A collection of builders for creating Nimbus {@link JWTProcessor} instances.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see NimbusJwtDecoder
 */
public final class JwtProcessors {

	/**
	 * Use the given
	 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 *
	 * @param jwkSetUri the JWK Set uri to use
	 * @return a {@link JwtProcessors} for further configurations
	 */
	public static JwkSetUriJwtProcessorBuilder withJwkSetUri(String jwkSetUri) {
		return new JwkSetUriJwtProcessorBuilder(jwkSetUri);
	}

	/**
	 * A builder for creating Nimbus {@link JWTProcessor} instances based on a
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 */
	public static final class JwkSetUriJwtProcessorBuilder {
		private String jwkSetUri;
		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
		private RestOperations restOperations = new RestTemplate();

		private JwkSetUriJwtProcessorBuilder(String jwkSetUri) {
			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
			this.jwkSetUri = jwkSetUri;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>.
		 *
		 * @param jwsAlgorithm the algorithm to use
		 * @return a {@link JwtProcessors} for further configurations
		 */
		public JwkSetUriJwtProcessorBuilder jwsAlgorithm(String jwsAlgorithm) {
			Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");
			this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);
			return this;
		}

		/**
		 * Use the given {@link RestOperations} to coordinate with the authorization servers indicated in the
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri
		 * as well as the
		 * <a href="http://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>.
		 *
		 * @param restOperations
		 * @return
		 */
		public JwkSetUriJwtProcessorBuilder restOperations(RestOperations restOperations) {
			Assert.notNull(restOperations, "restOperations cannot be null");
			this.restOperations = restOperations;
			return this;
		}

		/**
		 * Build the configured {@link JwtDecoder}.
		 *
		 * @return the configured {@link JwtDecoder}
		 */
		public JWTProcessor<SecurityContext> build() {
			ResourceRetriever jwkSetRetriever = new RestOperationsResourceRetriever(this.restOperations);
			JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(toURL(this.jwkSetUri), jwkSetRetriever);
			JWSKeySelector<SecurityContext> jwsKeySelector =
					new JWSVerificationKeySelector<>(this.jwsAlgorithm, jwkSource);
			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);

			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });

			return jwtProcessor;
		}

		private static URL toURL(String url) {
			try {
				return new URL(url);
			} catch (MalformedURLException ex) {
				throw new IllegalArgumentException("Invalid JWK Set URL \"" + url + "\" : " + ex.getMessage(), ex);
			}
		}

		private static class RestOperationsResourceRetriever implements ResourceRetriever {
			private final RestOperations restOperations;

			RestOperationsResourceRetriever(RestOperations restOperations) {
				Assert.notNull(restOperations, "restOperations cannot be null");
				this.restOperations = restOperations;
			}

			@Override
			public Resource retrieveResource(URL url) throws IOException {
				HttpHeaders headers = new HttpHeaders();
				headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));

				ResponseEntity<String> response;
				try {
					RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, url.toURI());
					response = this.restOperations.exchange(request, String.class);
				} catch (Exception ex) {
					throw new IOException(ex);
				}

				if (response.getStatusCodeValue() != 200) {
					throw new IOException(response.toString());
				}

				return new Resource(response.getBody(), "UTF-8");
			}
		}
	}
}
