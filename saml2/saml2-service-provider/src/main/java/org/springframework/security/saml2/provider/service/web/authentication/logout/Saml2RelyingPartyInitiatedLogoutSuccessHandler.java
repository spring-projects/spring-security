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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A success handler for issuing a SAML 2.0 Logout Request to the the SAML 2.0 Asserting
 * Party
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class Saml2RelyingPartyInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final Saml2LogoutRequestResolver logoutRequestResolver;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	/**
	 * Constructs a {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler} using the
	 * provided parameters
	 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
	 */
	public Saml2RelyingPartyInitiatedLogoutSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver) {
		this.logoutRequestResolver = logoutRequestResolver;
	}

	/**
	 * Produce and send a SAML 2.0 Logout Response based on the SAML 2.0 Logout Request
	 * received from the asserting party
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param authentication the current principal details
	 * @throws IOException when failing to write to the response
	 */
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException {
		Saml2LogoutRequest logoutRequest = this.logoutRequestResolver.resolve(request, authentication);
		if (logoutRequest == null) {
			this.logger.trace("Returning 401 since no logout request generated");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, request, response);
		if (logoutRequest.getBinding() == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, logoutRequest);
		}
		else {
			doPost(response, logoutRequest);
		}
	}

	/**
	 * Use this {@link Saml2LogoutRequestRepository} for saving the SAML 2.0 Logout
	 * Request
	 * @param logoutRequestRepository the {@link Saml2LogoutRequestRepository} to use
	 */
	public void setLogoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
		Assert.notNull(logoutRequestRepository, "logoutRequestRepository cannot be null");
		this.logoutRequestRepository = logoutRequestRepository;
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest)
			throws IOException {
		String location = logoutRequest.getLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location)
				.query(logoutRequest.getParametersQuery());
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void doPost(HttpServletResponse response, Saml2LogoutRequest logoutRequest) throws IOException {
		String location = logoutRequest.getLocation();
		String saml = logoutRequest.getSamlRequest();
		String relayState = logoutRequest.getRelayState();
		String html = createSamlPostRequestFormData(location, saml, relayState);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(String location, String saml, String relayState) {
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
		html.append("        <meta http-equiv=\"Content-Security-Policy\" ")
				.append("content=\"script-src 'sha256-t+jmhLjs1ocvgaHBJsFcgznRk68d37TLtbI3NE9h7EU='\">\n");
		html.append("        <meta charset=\"utf-8\" />\n");
		html.append("    </head>\n");
		html.append("    <body onload=\"document.forms[0].submit()\">\n");
		html.append("        <noscript>\n");
		html.append("            <p>\n");
		html.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n");
		html.append("                you must press the Continue button once to proceed.\n");
		html.append("            </p>\n");
		html.append("        </noscript>\n");
		html.append("        \n");
		html.append("        <form action=\"");
		html.append(location);
		html.append("\" method=\"post\">\n");
		html.append("            <div>\n");
		html.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"");
		html.append(HtmlUtils.htmlEscape(saml));
		html.append("\"/>\n");
		if (StringUtils.hasText(relayState)) {
			html.append("                <input type=\"hidden\" name=\"RelayState\" value=\"");
			html.append(HtmlUtils.htmlEscape(relayState));
			html.append("\"/>\n");
		}
		html.append("            </div>\n");
		html.append("            <noscript>\n");
		html.append("                <div>\n");
		html.append("                    <input type=\"submit\" value=\"Continue\"/>\n");
		html.append("                </div>\n");
		html.append("            </noscript>\n");
		html.append("        </form>\n");
		html.append("        \n");
		html.append("    </body>\n");
		html.append("    <script>window.onload = () => document.forms[0].submit();</script>\n");
		html.append("</html>");
		return html.toString();
	}

}
