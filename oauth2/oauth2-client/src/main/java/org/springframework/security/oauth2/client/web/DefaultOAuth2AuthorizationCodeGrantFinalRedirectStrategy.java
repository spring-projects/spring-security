package org.springframework.security.oauth2.client.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * Default implementation of {@link OAuth2AuthorizationCodeGrantFinalRedirectStrategy}.
 *
 * @author Tadaya Tsuyukubo
 * @since 5.2
 * @see OAuth2AuthorizationCodeGrantFilter
 */
public class DefaultOAuth2AuthorizationCodeGrantFinalRedirectStrategy implements OAuth2AuthorizationCodeGrantFinalRedirectStrategy {

	private final RedirectStrategy redirectStrategy;
	private final RequestCache requestCache;

	public DefaultOAuth2AuthorizationCodeGrantFinalRedirectStrategy(RedirectStrategy redirectStrategy, RequestCache requestCache) {
		this.redirectStrategy = redirectStrategy;
		this.requestCache = requestCache;
	}

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationResponse authorizationResponse) throws IOException {

		String redirectUrl = authorizationResponse.getRedirectUri();
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest != null) {
			redirectUrl = savedRequest.getRedirectUrl();
			this.requestCache.removeRequest(request, response);
		}

		this.redirectStrategy.sendRedirect(request, response, redirectUrl);
	}

}
