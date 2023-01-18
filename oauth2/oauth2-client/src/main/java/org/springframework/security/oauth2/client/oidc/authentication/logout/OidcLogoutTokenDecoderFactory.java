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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenClaimsVerifier;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * A {@link JwtDecoderFactory} that decodes and verifies OIDC Logout Tokens.
 *
 * @author Josh Cummings
 * @since 6.1
 * @see OidcLogoutToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout
 * Token</a>
 */
public final class OidcLogoutTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {

	private final Map<String, JwtDecoder> jwtDecoderByRegistrationId = new ConcurrentHashMap<>();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public JwtDecoder createDecoder(ClientRegistration context) {
		ClientID clientId = new ClientID(context.getClientId());
		Issuer issuer = new Issuer(context.getProviderDetails().getIssuerUri());
		LogoutTokenClaimsVerifier verifier = new LogoutTokenClaimsVerifier(issuer, clientId);
		return this.jwtDecoderByRegistrationId.computeIfAbsent(context.getRegistrationId(),
				(k) -> NimbusJwtDecoder.withJwkSetUri(context.getProviderDetails().getJwkSetUri())
						.jwtProcessorCustomizer((jwtProcessor) -> jwtProcessor.setJWTClaimsSetVerifier(verifier))
						.build());
	}

}
