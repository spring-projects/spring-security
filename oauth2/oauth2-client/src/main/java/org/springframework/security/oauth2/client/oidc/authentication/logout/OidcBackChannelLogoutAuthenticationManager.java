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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.logout.BackchannelLogoutAuthentication;
import org.springframework.util.Assert;

public final class OidcBackChannelLogoutAuthenticationManager implements AuthenticationManager {

	private JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory;

	private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

	public OidcBackChannelLogoutAuthenticationManager() {
		OidcIdTokenDecoderFactory logoutTokenDecoderFactory = new OidcIdTokenDecoderFactory();
		logoutTokenDecoderFactory.setJwtValidatorFactory(new DefaultOidcLogoutTokenValidatorFactory());
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof LogoutTokenAuthenticationToken token)) {
			return null;
		}
		String logoutToken = token.getLogoutToken();
		ClientRegistration registration = token.getClientRegistration();
		Jwt jwt = decode(registration, logoutToken);
		OidcLogoutToken oidcLogoutToken = OidcLogoutToken.withTokenValue(logoutToken)
				.claims((claims) -> claims.putAll(jwt.getClaims())).build();
		Iterable<? extends SessionInformation> sessions = this.sessionRegistry.deregister(oidcLogoutToken);
		return new BackchannelLogoutAuthentication(oidcLogoutToken, oidcLogoutToken, sessions);
	}

	private Jwt decode(ClientRegistration registration, String token) {
		JwtDecoder logoutTokenDecoder = this.logoutTokenDecoderFactory.createDecoder(registration);
		try {
			return logoutTokenDecoder.decode(token);
		}
		catch (BadJwtException failed) {
			throw new BadCredentialsException(failed.getMessage(), failed);
		}
		catch (JwtException failed) {
			throw new AuthenticationServiceException(failed.getMessage(), failed);
		}
	}

	public void setLogoutTokenDecoderFactory(JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory) {
		Assert.notNull(logoutTokenDecoderFactory, "logoutTokenDecoderFactory cannot be null");
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

	public void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

}
