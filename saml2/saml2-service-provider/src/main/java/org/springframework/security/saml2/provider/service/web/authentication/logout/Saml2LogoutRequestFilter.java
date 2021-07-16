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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutAuthenticatorResult;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestAuthenticator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestAuthenticatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * A filter for handling logout requests in the form of a &lt;saml2:LogoutRequest&gt; sent
 * from the asserting party.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class Saml2LogoutRequestFilter extends OncePerRequestFilter {

	private static final String DEFAULT_LOGOUT_ENDPOINT = "/logout/saml2/slo";

	private RequestMatcher logoutRequestMatcher = new AntPathRequestMatcher(DEFAULT_LOGOUT_ENDPOINT);

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final Saml2LogoutRequestAuthenticator logoutRequestAuthenticator;

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private final LogoutHandler logoutHandler;

	private final Saml2LogoutResponseResolver logoutResponseResolver;

	/**
	 * Constructs a {@link Saml2LogoutResponseFilter} for accepting SAML 2.0 Logout
	 * Requests from the asserting party
	 * @param relyingPartyRegistrationResolver the strategy for resolving a
	 * {@link RelyingPartyRegistration}
	 * @param logoutRequestAuthenticator the SAML 2.0 Logout Request authenticator
	 * @param logoutHandler the handler for handling logout, once the SAML 2.0 Logout
	 * Request is authenticated
	 * @param logoutResponseResolver the resolver that formulates the SAML 2.0 Logout
	 * Response after logout has completed that handles other logout concerns
	 */
	public Saml2LogoutRequestFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			Saml2LogoutRequestAuthenticator logoutRequestAuthenticator, LogoutHandler logoutHandler,
			Saml2LogoutResponseResolver logoutResponseResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.logoutRequestAuthenticator = logoutRequestAuthenticator;
		this.logoutResponseResolver = logoutResponseResolver;
		this.logoutHandler = logoutHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		if (!this.logoutRequestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}

		if (request.getParameter("SAMLRequest") == null) {
			chain.doFilter(request, response);
			return;
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String serialized = request.getParameter("SAMLRequest");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				getRegistrationId(authentication));
		if (registration == null) {
			chain.doFilter(request, response);
			return;
		}

		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(serialized).relayState(request.getParameter("RelayState"))
				.parameters((params) -> params.put("SigAlg", request.getParameter("SigAlg")))
				.parameters((params) -> params.put("Signature", request.getParameter("Signature"))).build();
		Saml2LogoutRequestAuthenticatorParameters parameters = new Saml2LogoutRequestAuthenticatorParameters(
				logoutRequest, registration, authentication);
		Saml2LogoutAuthenticatorResult result = this.logoutRequestAuthenticator.authenticate(parameters);
		if (result.hasErrors()) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrors().iterator().next().toString());
			return;
		}
		this.logoutHandler.logout(request, response, authentication);
		Saml2LogoutResponse logoutResponse = this.logoutResponseResolver.resolveLogoutResponse(request, authentication)
				.logoutResponse();
		if (logoutResponse.getBinding() == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, logoutResponse);
		}
		else {
			doPost(response, logoutResponse);
		}
	}

	/**
	 * Use this {@link RequestMatcher} for identifying which requests this filter should
	 * process
	 * @param logoutRequestMatcher the {@link RequestMatcher} to use
	 */
	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		this.logoutRequestMatcher = logoutRequestMatcher;
	}

	private String getRegistrationId(Authentication authentication) {
		if (authentication instanceof Saml2Authentication) {
			return ((Saml2Authentication) authentication).getRelyingPartyRegistrationId();
		}
		return null;
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response,
			Saml2LogoutResponse logoutResponse) throws IOException {
		String location = logoutResponse.getResponseLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location);
		addParameter("SAMLResponse", logoutResponse, uriBuilder);
		addParameter("RelayState", logoutResponse, uriBuilder);
		addParameter("SigAlg", logoutResponse, uriBuilder);
		addParameter("Signature", logoutResponse, uriBuilder);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void addParameter(String name, Saml2LogoutResponse logoutResponse, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(logoutResponse.getParameter(name))) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(logoutResponse.getParameter(name), StandardCharsets.ISO_8859_1));
		}
	}

	private void doPost(HttpServletResponse response, Saml2LogoutResponse logoutResponse) throws IOException {
		String html = createSamlPostRequestFormData(logoutResponse);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2LogoutResponse logoutResponse) {
		String location = logoutResponse.getResponseLocation();
		String samlRequest = logoutResponse.getSamlResponse();
		String relayState = logoutResponse.getRelayState();
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
		html.append("                <input type=\"hidden\" name=\"SAMLResponse\" value=\"");
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
