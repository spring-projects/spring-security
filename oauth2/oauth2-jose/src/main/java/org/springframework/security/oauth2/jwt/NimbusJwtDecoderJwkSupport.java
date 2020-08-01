/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.Collections;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

/**
 * An implementation of a {@link JwtDecoder} that "decodes" a JSON Web Token (JWT) and
 * additionally verifies it's digital signature if the JWT is a JSON Web Signature (JWS).
 * The public key used for verification is obtained from the JSON Web Key (JWK) Set
 * {@code URL} supplied via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK internally.
 *
 * @deprecated Use {@link NimbusJwtDecoder} or {@link JwtDecoders} instead
 * @author Joe Grandja
 * @author Josh Cummings
 * @since 5.0
 * @see JwtDecoder
 * @see NimbusJwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key
 * (JWK)</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus
 * JOSE + JWT SDK</a>
 */
@Deprecated
public final class NimbusJwtDecoderJwkSupport implements JwtDecoder {

	private NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder jwtDecoderBuilder;

	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
			.withDefaults(Collections.emptyMap());

	private NimbusJwtDecoder delegate;

	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 */
	public NimbusJwtDecoderJwkSupport(String jwkSetUrl) {
		this(jwkSetUrl, JwsAlgorithms.RS256);
	}

	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 * @param jwsAlgorithm the JSON Web Algorithm (JWA) used for verifying the digital
	 * signatures
	 */
	public NimbusJwtDecoderJwkSupport(String jwkSetUrl, String jwsAlgorithm) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");
		this.jwtDecoderBuilder = NimbusJwtDecoder.withJwkSetUri(jwkSetUrl)
				.jwsAlgorithm(SignatureAlgorithm.from(jwsAlgorithm));
		this.delegate = makeDelegate();
	}

	private NimbusJwtDecoder makeDelegate() {
		NimbusJwtDecoder delegate = this.jwtDecoderBuilder.build();
		delegate.setClaimSetConverter(this.claimSetConverter);
		delegate.setJwtValidator(this.jwtValidator);
		return delegate;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		return this.delegate.decode(token);
	}

	/**
	 * Use this {@link Jwt} Validator
	 * @param jwtValidator - the Jwt Validator to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
		this.delegate.setJwtValidator(jwtValidator);
	}

	/**
	 * Use the following {@link Converter} for manipulating the JWT's claim set
	 * @param claimSetConverter the {@link Converter} to use
	 */
	public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
		Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
		this.claimSetConverter = claimSetConverter;
		this.delegate.setClaimSetConverter(claimSetConverter);
	}

	/**
	 * Sets the {@link RestOperations} used when requesting the JSON Web Key (JWK) Set.
	 * @param restOperations the {@link RestOperations} used when requesting the JSON Web
	 * Key (JWK) Set
	 * @since 5.1
	 */
	public void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.jwtDecoderBuilder = this.jwtDecoderBuilder.restOperations(restOperations);
		this.delegate = makeDelegate();
	}

}
