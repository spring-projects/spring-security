/*
 * Copyright 2002-2022 the original author or authors.
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
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
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
 * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>
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
		if (authentication instanceof OAuth2AuthenticationToken && authentication.getPrincipal() instanceof OidcUser) {
			String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
			ClientRegistration clientRegistration = this.clientRegistrationRepository
					.findByRegistrationId(registrationId);
			URI endSessionEndpoint = this.endSessionEndpoint(clientRegistration);
			if (endSessionEndpoint != null) {
				String idToken = idToken(authentication);
				String postLogoutRedirectUri = postLogoutRedirectUri(request, clientRegistration);
				targetUrl = endpointUri(endSessionEndpoint, idToken, postLogoutRedirectUri);
			}
		}
		return (targetUrl != null) ? targetUrl : super.determineTargetUrl(request, response);
	}

	private URI endSessionEndpoint(ClientRegistration clientRegistration) {
		if (clientRegistration != null) {
			ProviderDetails providerDetails = clientRegistration.getProviderDetails();
			Object endSessionEndpoint = providerDetails.getConfigurationMetadata().get("end_session_endpoint");
			if (endSessionEndpoint != null) {
				return URI.create(endSessionEndpoint.toString());
			}
		}
		return null;
	}

	private String idToken(Authentication authentication) {
		return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
	}

	private String postLogoutRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		if (this.postLogoutRedirectUri == null) {
			return null;
		}
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder
				.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build();

		Map<String, String> uriVariables = new HashMap<>();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");

		String path = uriComponents.getPath();
		uriVariables.put("basePath", (path != null) ? path : "");

		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
	}

	private String endpointUri(URI endSessionEndpoint, String idToken, String postLogoutRedirectUri) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
		builder.queryParam("id_token_hint", idToken);
		if (postLogoutRedirectUri != null) {
			builder.queryParam("post_logout_redirect_uri", postLogoutRedirectUri);
		}
		// @formatter:off
		return builder.encode(StandardCharsets.UTF_8)
				.build()
				.toUriString();
		// @formatter:on
	}

	/**
	 * Set the post logout redirect uri template.
	 *
	 * <br />
	 * The supported uri template variables are: {@code {baseScheme}}, {@code {baseHost}},
	 * {@code {basePort}} and {@code {basePath}}.
	 *
	 * <br />
	 * <b>NOTE:</b> {@code "{baseUrl}"} is also supported, which is the same as
	 * {@code "{baseScheme}://{baseHost}{basePort}{basePath}"}
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
