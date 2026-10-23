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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.util.Map;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.util.Assert;

/**
 * A {@link JwtDecoderFactory factory} that creates a {@link JwtDecoder} for the signed
 * and/or encrypted UserInfo Response of an OpenID Connect 1.0 Provider, which is returned
 * as a JWT with the {@code application/jwt} content type.
 *
 * <p>
 * The {@link JwtDecoder} is associated to a specific {@link ClientRegistration}. It
 * verifies the signature of the response, following the same rules as the
 * {@link OidcIdTokenDecoderFactory}: it uses the keys of the Provider's
 * {@link ClientRegistration.ProviderDetails#getJwkSetUri() JWK Set} for an asymmetric
 * {@link #setJwsAlgorithmResolver(Function) algorithm} and the
 * {@link ClientRegistration#getClientSecret() client secret} for a HMAC one. It then
 * validates the response as follows:
 * <ul>
 * <li>the {@code iss} claim, when present, must match the Provider's
 * {@link ClientRegistration.ProviderDetails#getIssuerUri() issuer}, when it is
 * configured</li>
 * <li>the {@code aud} claim, when present, must contain the
 * {@link ClientRegistration#getClientId() client id}</li>
 * <li>the {@code exp} and {@code nbf} claims, when present</li>
 * </ul>
 *
 * <p>
 * If the Provider also encrypts the response, which then has to be signed first and
 * encrypted afterwards, configure the key used to decrypt it using
 * {@link #setJweDecryptionKeyResolver(Function)}.
 *
 * <p>
 * Use it with {@link DefaultOAuth2UserService#setJwtResponseConverter}:
 *
 * <pre>
 *     OidcUserInfoJwtDecoderFactory decoderFactory = new OidcUserInfoJwtDecoderFactory();
 *     DefaultOAuth2UserService userService = new DefaultOAuth2UserService();
 *     userService.setJwtResponseConverter((userRequest) -> (jwt) ->
 *         decoderFactory.createDecoder(userRequest.getClientRegistration()).decode(jwt).getClaims());
 *     OidcUserService oidcUserService = new OidcUserService();
 *     oidcUserService.setOauth2UserService(userService);
 * </pre>
 *
 * @author Sharang Gupta
 * @since 7.2
 * @see JwtDecoderFactory
 * @see ClientRegistration
 * @see DefaultOAuth2UserService#setJwtResponseConverter
 * @see <a href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect
 * Core 1.0, Successful UserInfo Response</a>
 */
public final class OidcUserInfoJwtDecoderFactory implements JwtDecoderFactory<ClientRegistration> {

	private final OidcIdTokenDecoderFactory signatureVerifierFactory = new OidcIdTokenDecoderFactory();

	private Function<ClientRegistration, @Nullable JWK> jweDecryptionKeyResolver = (clientRegistration) -> null;

	/**
	 * Constructs an {@code OidcUserInfoJwtDecoderFactory}.
	 */
	public OidcUserInfoJwtDecoderFactory() {
		this.signatureVerifierFactory.setJwtValidatorFactory((clientRegistration) -> JwtValidators
			.createDefaultWithValidators(new OidcUserInfoJwtValidator(clientRegistration)));
	}

	@Override
	public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		JwtDecoder signatureVerifier = this.signatureVerifierFactory.createDecoder(clientRegistration);
		return new JweDecryptingJwtDecoder(signatureVerifier, clientRegistration, this.jweDecryptionKeyResolver);
	}

	/**
	 * Sets the resolver that provides the expected {@link JwsAlgorithm JWS algorithm}
	 * used for the signature or MAC on the UserInfo Response, which is the
	 * {@code userinfo_signed_response_alg} the client has registered with the Provider.
	 * The default resolves to
	 * {@link org.springframework.security.oauth2.jose.jws.SignatureAlgorithm#RS256 RS256}
	 * for all {@link ClientRegistration clients}.
	 * @param jwsAlgorithmResolver the resolver that provides the expected
	 * {@link JwsAlgorithm JWS algorithm} for a specific {@link ClientRegistration client}
	 */
	public void setJwsAlgorithmResolver(Function<ClientRegistration, JwsAlgorithm> jwsAlgorithmResolver) {
		Assert.notNull(jwsAlgorithmResolver, "jwsAlgorithmResolver cannot be null");
		this.signatureVerifierFactory.setJwsAlgorithmResolver(jwsAlgorithmResolver);
	}

	/**
	 * Sets the factory that provides an {@link OAuth2TokenValidator}, which is used by
	 * the {@link JwtDecoder}. The default composes the standard validators of
	 * {@link JwtValidators#createDefaultWithValidators} with one that validates the
	 * {@code iss} and {@code aud} claims.
	 * @param jwtValidatorFactory the factory that provides an
	 * {@link OAuth2TokenValidator}
	 */
	public void setJwtValidatorFactory(Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory) {
		Assert.notNull(jwtValidatorFactory, "jwtValidatorFactory cannot be null");
		this.signatureVerifierFactory.setJwtValidatorFactory(jwtValidatorFactory);
	}

	/**
	 * Sets the factory that provides a {@link Converter} used for type conversion of
	 * claim values for the UserInfo Response. The default is the
	 * {@link OidcIdTokenDecoderFactory#createDefaultClaimTypeConverter() converter used
	 * for ID Tokens} for all {@link ClientRegistration clients}.
	 * @param claimTypeConverterFactory the factory that provides a {@link Converter} used
	 * for type conversion of claim values for a specific {@link ClientRegistration
	 * client}
	 */
	public void setClaimTypeConverterFactory(
			Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory) {
		Assert.notNull(claimTypeConverterFactory, "claimTypeConverterFactory cannot be null");
		this.signatureVerifierFactory.setClaimTypeConverterFactory(claimTypeConverterFactory);
	}

	/**
	 * Sets the resolver that provides the {@link JWK} holding the private (or secret) key
	 * used to decrypt an encrypted UserInfo Response, which is the key that matches the
	 * {@code userinfo_encrypted_response_alg} the client has registered with the
	 * Provider. The default resolves to {@code null} for all {@link ClientRegistration
	 * clients}, which rejects an encrypted response.
	 * <p>
	 * The encrypted response has to contain the signed JWT, as OpenID Connect requires
	 * that a response is signed before it is encrypted. RSA, EC and symmetric keys are
	 * supported.
	 * @param jweDecryptionKeyResolver the resolver that provides the {@link JWK} used to
	 * decrypt the response for a specific {@link ClientRegistration client}
	 */
	public void setJweDecryptionKeyResolver(Function<ClientRegistration, @Nullable JWK> jweDecryptionKeyResolver) {
		Assert.notNull(jweDecryptionKeyResolver, "jweDecryptionKeyResolver cannot be null");
		this.jweDecryptionKeyResolver = jweDecryptionKeyResolver;
	}

}
