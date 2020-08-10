/*
 * Copyright 2002-2020 the original author or authors.
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
import java.util.Collections;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A logout success handler for initiating OIDC logout through the user agent.
 *
 * @author Josh Cummings
 * @since 5.2
 * @see <a href=
 * "https://openid.net/specs/openid-connect-session-1_0.html#RPLogout">RP-Initiated
 * Logout</a>
 * @see org.springframework.security.web.authentication.logout.LogoutSuccessHandler
 */
public final class OidcClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

	private final ClientRegistrationRepository clientRegistrationRepository;

	private String postLogoutRedirectUri;

	public OidcClientInitiatedLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		String targetUrl = null;
		URI endSessionEndpoint;
		if (authentication instanceof OAuth2AuthenticationToken && authentication.getPrincipal() instanceof OidcUser) {
			String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
			ClientRegistration clientRegistration = this.clientRegistrationRepository
					.findByRegistrationId(registrationId);
			endSessionEndpoint = this.endSessionEndpoint(clientRegistration);
			if (endSessionEndpoint != null) {
				String idToken = idToken(authentication);
				URI postLogoutRedirectUri = postLogoutRedirectUri(request);
				targetUrl = endpointUri(endSessionEndpoint, idToken, postLogoutRedirectUri);
			}
		}
		if (targetUrl == null) {
			targetUrl = super.determineTargetUrl(request, response);
		}

		return targetUrl;
	}

	private URI endSessionEndpoint(ClientRegistration clientRegistration) {
		URI result = null;
		if (clientRegistration != null) {
			Object endSessionEndpoint = clientRegistration.getProviderDetails().getConfigurationMetadata()
					.get("end_session_endpoint");
			if (endSessionEndpoint != null) {
				result = URI.create(endSessionEndpoint.toString());
			}
		}

		return result;
	}

	private String idToken(Authentication authentication) {
		return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
	}

	private URI postLogoutRedirectUri(HttpServletRequest request) {
		if (this.postLogoutRedirectUri == null) {
			return null;
		}
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath()).replaceQuery(null).fragment(null).build();
		return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
				.buildAndExpand(Collections.singletonMap("baseUrl", uriComponents.toUriString())).toUri();
	}

	private String endpointUri(URI endSessionEndpoint, String idToken, URI postLogoutRedirectUri) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
		builder.queryParam("id_token_hint", idToken);
		if (postLogoutRedirectUri != null) {
			builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
		}
		return builder.encode(StandardCharsets.UTF_8).build().toUriString();
	}

	/**
	 * Set the post logout redirect uri to use
	 * @param postLogoutRedirectUri - A valid URL to which the OP should redirect after
	 * logging out the user
	 * @deprecated {@link #setPostLogoutRedirectUri(String)}
	 */
	@Deprecated
	public void setPostLogoutRedirectUri(URI postLogoutRedirectUri) {
		Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null");
		this.postLogoutRedirectUri = postLogoutRedirectUri.toASCIIString();
	}

	/**
	 * Set the post logout redirect uri template to use. Supports the {@code "{baseUrl}"}
	 * placeholder, for example:
	 *
	 * <pre>
	 * 	handler.setPostLogoutRedirectUri("{baseUrl}");
	 * </pre>
	 *
	 * will make so that {@code post_logout_redirect_uri} will be set to the base url for
	 * the client application.
	 * @param postLogoutRedirectUri - A template for creating the
	 * {@code post_logout_redirect_uri} query parameter
	 * @since 5.3
	 */
	public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
		Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null");
		this.postLogoutRedirectUri = postLogoutRedirectUri;
	}

}
