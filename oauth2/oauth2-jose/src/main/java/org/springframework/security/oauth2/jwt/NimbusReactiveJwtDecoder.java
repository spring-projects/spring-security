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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of a {@link ReactiveJwtDecoder} that &quot;decodes&quot; a
 * JSON Web Token (JWT) and additionally verifies it's digital signature if the JWT is a
 * JSON Web Signature (JWS). The public key used for verification is obtained from the
 * JSON Web Key (JWK) Set {@code URL} supplied via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK internally.
 *
 * @author Rob Winch
 * @since 5.1
 * @see ReactiveJwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE + JWT SDK</a>
 */
public final class NimbusReactiveJwtDecoder<T extends SecurityContext> implements ReactiveJwtDecoder {
	private final ReactiveJWTProcessor jwtProcessor;

	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();
	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
			.withDefaults(Collections.emptyMap());

	public NimbusReactiveJwtDecoder(String jwksUri){
		this(new ReactiveJWKSJWTProcessor(jwksUri));
	}

	public NimbusReactiveJwtDecoder(RSAPublicKey publicKey){
		this(new ReactivePublicKeyJWTProcessor(publicKey));
	}

	public NimbusReactiveJwtDecoder(ReactiveJWTProcessor jwtProcessor){
		this.jwtProcessor=jwtProcessor;
	}

	/**
	 * Use the provided {@link OAuth2TokenValidator} to validate incoming {@link Jwt}s.
	 *
	 * @param jwtValidator the {@link OAuth2TokenValidator} to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
	}

	/**
	 * Use the following {@link Converter} for manipulating the JWT's claim set
	 *
	 * @param claimSetConverter the {@link Converter} to use
	 */
	public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
		Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
		this.claimSetConverter = claimSetConverter;
	}

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		JWT jwt = parse(token);
		if (jwt instanceof SignedJWT) {
			return this.decode((SignedJWT) jwt);
		}
		throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Mono<Jwt> decode(SignedJWT parsedToken) {
		try {
			return jwtProcessor.process(parsedToken)
				.onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof JwtException), e -> new IllegalStateException("Could not obtain the keys", e))
				.map(set -> createJwt(parsedToken, set))
				.map(this::validateJwt)
				.onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof JwtException), e -> new JwtException("An error occurred while attempting to decode the Jwt: ", e));
		} catch (RuntimeException ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Jwt createJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
		Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
		Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());

		Instant expiresAt = (Instant) claims.get(JwtClaimNames.EXP);
		Instant issuedAt = (Instant) claims.get(JwtClaimNames.IAT);
		return new Jwt(parsedJwt.getParsedString(), issuedAt, expiresAt, headers, claims);
	}

	private Jwt validateJwt(Jwt jwt) {
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);

		if ( result.hasErrors() ) {
			String message = result.getErrors().iterator().next().getDescription();
			throw new JwtValidationException(message, result.getErrors());
		}

		return jwt;
	}
}
