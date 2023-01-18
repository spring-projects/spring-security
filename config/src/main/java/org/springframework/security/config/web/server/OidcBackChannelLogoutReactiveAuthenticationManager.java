/*
 * Copyright 2002-2023 the original author or authors.
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

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.util.Assert;

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
		ReactiveOidcIdTokenDecoderFactory logoutTokenDecoderFactory = new ReactiveOidcIdTokenDecoderFactory();
		logoutTokenDecoderFactory.setJwtValidatorFactory(new DefaultOidcLogoutTokenValidatorFactory());
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
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
				.map((jwt) -> OidcLogoutToken
						.withTokenValue(logoutToken)
						.claims((claims) -> claims.putAll(jwt.getClaims())).build()
				)
				.map(OidcBackChannelLogoutAuthentication::new);
	}

	private Mono<Jwt> decode(ClientRegistration registration, String token) {
		ReactiveJwtDecoder logoutTokenDecoder = this.logoutTokenDecoderFactory.createDecoder(registration);
		try {
			return logoutTokenDecoder.decode(token);
		}
		catch (BadJwtException failed) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, failed.getMessage(),
					"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
			return Mono.error(new OAuth2AuthenticationException(error, failed));
		}
		catch (Exception failed) {
			return Mono.error(new AuthenticationServiceException(failed.getMessage(), failed));
		}
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
