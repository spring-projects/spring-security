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

package org.springframework.security.oauth2.client.oidc.web.logout;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A logout success handler for initiating OIDC logout through the user agent.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see <a href="https://openid.net/specs/openid-connect-session-1_0.html#RPLogout">RP-Initiated Logout</a>
 * @see org.springframework.security.web.authentication.logout.LogoutSuccessHandler
 */
public final class OidcClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
	private final ClientRegistrationRepository clientRegistrationRepository;

	private URI postLogoutRedirectUri;

	public OidcClientInitiatedLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	protected String determineTargetUrl(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication) {
		String targetUrl = null;
		URI endSessionEndpoint;
		if (authentication instanceof OAuth2AuthenticationToken && authentication.getPrincipal() instanceof OidcUser) {
			endSessionEndpoint = this.endSessionEndpoint((OAuth2AuthenticationToken) authentication);
			if (endSessionEndpoint != null) {
				targetUrl = endpointUri(endSessionEndpoint, authentication);
			}
		}
		if (targetUrl == null) {
			targetUrl = super.determineTargetUrl(request, response);
		}

		return targetUrl;
	}

	private URI endSessionEndpoint(OAuth2AuthenticationToken token) {
		String registrationId = token.getAuthorizedClientRegistrationId();
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		Object endSessionEndpoint = clientRegistration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");

		URI result = null;
		if (endSessionEndpoint != null) {
			result = URI.create(endSessionEndpoint.toString());
		}

		return result;
	}

	private String endpointUri(URI endSessionEndpoint, Authentication authentication) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
		builder.queryParam("id_token_hint", idToken(authentication));
		if (this.postLogoutRedirectUri != null) {
			builder.queryParam("post_logout_redirect_uri", this.postLogoutRedirectUri);
		}
		return builder.encode(StandardCharsets.UTF_8).build().toUriString();
	}

	private String idToken(Authentication authentication) {
		return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
	}

	/**
	 * Set the post logout redirect uri to use
	 *
	 * @param postLogoutRedirectUri - A valid URL to which the OP should redirect after logging out the user
	 */
	public void setPostLogoutRedirectUri(URI postLogoutRedirectUri) {
		Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null");
		this.postLogoutRedirectUri = postLogoutRedirectUri;
	}
}
