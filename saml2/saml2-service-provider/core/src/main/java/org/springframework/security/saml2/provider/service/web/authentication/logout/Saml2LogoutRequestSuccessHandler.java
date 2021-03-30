/*
 * Copyright 2002-2021 the original author or authors.
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
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.web.util.UriUtils;

/**
 * A success handler for issuing a SAML 2.0 Logout Response in response to the SAML 2.0
 * Logout Request that the SAML 2.0 Asserting Party sent
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class Saml2LogoutRequestSuccessHandler implements LogoutSuccessHandler {

	private final Saml2LogoutRequestResolver logoutRequestResolver;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	/**
	 * Constructs a {@link Saml2LogoutRequestSuccessHandler} using the provided parameters
	 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
	 */
	public Saml2LogoutRequestSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver) {
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
		Saml2LogoutRequestResolver.Saml2LogoutRequestBuilder<?> builder = this.logoutRequestResolver
				.resolveLogoutRequest(request, authentication);
		if (builder == null) {
			return;
		}
		Saml2LogoutRequest logoutRequest = builder.logoutRequest();
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, request, response);
		if (logoutRequest.getBinding() == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, logoutRequest);
		}
		else {
			doPost(response, logoutRequest);
		}
	}

	public void setLogoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
		Assert.notNull(logoutRequestRepository, "logoutRequestRepository cannot be null");
		this.logoutRequestRepository = logoutRequestRepository;
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest)
			throws IOException {
		String location = logoutRequest.getLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location);
		addParameter("SAMLRequest", logoutRequest, uriBuilder);
		addParameter("RelayState", logoutRequest, uriBuilder);
		addParameter("SigAlg", logoutRequest, uriBuilder);
		addParameter("Signature", logoutRequest, uriBuilder);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void addParameter(String name, Saml2LogoutRequest logoutRequest, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(logoutRequest.getParameter(name))) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(logoutRequest.getParameter(name), StandardCharsets.ISO_8859_1));
		}
	}

	private void doPost(HttpServletResponse response, Saml2LogoutRequest logoutRequest) throws IOException {
		String html = createSamlPostRequestFormData(logoutRequest);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2LogoutRequest logoutRequest) {
		String location = logoutRequest.getLocation();
		String samlRequest = logoutRequest.getSamlRequest();
		String relayState = logoutRequest.getRelayState();
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
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
		html.append(HtmlUtils.htmlEscape(samlRequest));
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
		html.append("</html>");
		return html.toString();
	}

}
