package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Strategy interface to perform final redirect at the end of OAuth2 Authorization Code Grant Flow.
 *
 * @author Tadaya Tsuyukubo
 * @since 5.2
 * @see OAuth2AuthorizationCodeGrantFilter
 */
public interface OAuth2AuthorizationCodeGrantFinalRedirectStrategy {

	void sendRedirect(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationRequest authorizationRequest,
			OAuth2AuthorizationResponse authorizationResponse) throws IOException;

}
