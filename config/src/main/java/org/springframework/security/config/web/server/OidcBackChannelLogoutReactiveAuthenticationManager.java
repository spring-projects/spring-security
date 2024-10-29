/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.web.server;

import java.util.function.Function;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWKSecurityContext;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} that authenticates an OIDC Logout Token; namely
 * deserializing it, verifying its signature, and validating its claims.
 *
 * <p>
 * Intended to be included in a
 * {@link org.springframework.security.authentication.ProviderManager}
 *
 * @author Josh Cummings
 * @since 6.2
 * @see OidcLogoutAuthenticationToken
 * @see org.springframework.security.authentication.ProviderManager
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel
 * Logout</a>
 */
final class OidcBackChannelLogoutReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private ReactiveJwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory;

	/**
	 * Construct an {@link OidcBackChannelLogoutReactiveAuthenticationManager}
	 */
	OidcBackChannelLogoutReactiveAuthenticationManager() {
		Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidator = (clientRegistration) -> JwtValidators
			.createDefaultWithValidators(new OidcBackChannelLogoutTokenValidator(clientRegistration));
		this.logoutTokenDecoderFactory = (clientRegistration) -> {
			String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
			if (!StringUtils.hasText(jwkSetUri)) {
				OAuth2Error oauth2Error = new OAuth2Error("missing_signature_verifier",
						"Failed to find a Signature Verifier for Client Registration: '"
								+ clientRegistration.getRegistrationId()
								+ "'. Check to ensure you have configured the JwkSet URI.",
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			JOSEObjectTypeVerifier<JWKSecurityContext> typeVerifier = new DefaultJOSEObjectTypeVerifier<>(null,
					JOSEObjectType.JWT, new JOSEObjectType("logout+jwt"));
			NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
				.jwtProcessorCustomizer((processor) -> processor.setJWSTypeVerifier(typeVerifier))
				.build();
			decoder.setJwtValidator(jwtValidator.apply(clientRegistration));
			decoder.setClaimSetConverter(
					new ClaimTypeConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()));
			return decoder;
		};
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof OidcLogoutAuthenticationToken token)) {
			return Mono.empty();
		}
		String logoutToken = token.getLogoutToken();
		ClientRegistration registration = token.getClientRegistration();
		return decode(registration, logoutToken)
			.map((jwt) -> OidcLogoutToken.withTokenValue(logoutToken)
				.claims((claims) -> claims.putAll(jwt.getClaims()))
				.build())
			.map((oidcLogoutToken) -> new OidcBackChannelLogoutAuthentication(oidcLogoutToken, registration));
	}

	private Mono<Jwt> decode(ClientRegistration registration, String token) {
		ReactiveJwtDecoder logoutTokenDecoder = this.logoutTokenDecoderFactory.createDecoder(registration);
		return logoutTokenDecoder.decode(token).onErrorResume(Exception.class, (ex) -> {
			if (ex instanceof BadJwtException) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, ex.getMessage(),
						"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
				return Mono.error(new OAuth2AuthenticationException(error, ex));
			}
			return Mono.error(new AuthenticationServiceException(ex.getMessage(), ex));
		});
	}

	/**
	 * Use this {@link ReactiveJwtDecoderFactory} to generate {@link JwtDecoder}s that
	 * correspond to the {@link ClientRegistration} associated with the OIDC logout token.
	 * @param logoutTokenDecoderFactory the {@link JwtDecoderFactory} to use
	 */
	void setLogoutTokenDecoderFactory(ReactiveJwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory) {
		Assert.notNull(logoutTokenDecoderFactory, "logoutTokenDecoderFactory cannot be null");
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

}
