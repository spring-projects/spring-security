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

package org.springframework.security.saml2.provider.service.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * This {@code Filter} formulates a
 * <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">SAML 2.0
 * AuthnRequest</a> (line 1968) and redirects to a configured asserting party.
 *
 * <p>
 * It supports the <a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">HTTP-Redirect</a>
 * (line 520) and <a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">HTTP-POST</a>
 * (line 753) bindings.
 *
 * <p>
 * By default, this {@code Filter} responds to authentication requests at the {@code URI}
 * {@code /saml2/authenticate/{registrationId}}. The {@code URI} template variable
 * {@code {registrationId}} represents the
 * {@link RelyingPartyRegistration#getRegistrationId() registration identifier} of the
 * relying party that is used for initiating the authentication request.
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationRequestFilter extends OncePerRequestFilter {

	private final Saml2AuthenticationRequestResolver authenticationRequestResolver;

	private Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = new HttpSessionSaml2AuthenticationRequestRepository();

	/**
	 * Construct a {@link Saml2WebSsoAuthenticationRequestFilter} with the strategy for
	 * resolving the {@code AuthnRequest}
	 * @param authenticationRequestResolver the strategy for resolving the
	 * {@code AuthnRequest}
	 * @since 5.7
	 */
	public Saml2WebSsoAuthenticationRequestFilter(Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		Assert.notNull(authenticationRequestResolver, "authenticationRequestResolver cannot be null");
		this.authenticationRequestResolver = authenticationRequestResolver;
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to save the
	 * authentication request
	 * @param authenticationRequestRepository the
	 * {@link Saml2AuthenticationRequestRepository} to use
	 * @since 5.6
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.authenticationRequestRepository = authenticationRequestRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestResolver.resolve(request);
		if (authenticationRequest == null) {
			filterChain.doFilter(request, response);
			return;
		}
		if (authenticationRequest instanceof Saml2RedirectAuthenticationRequest) {
			sendRedirect(request, response, (Saml2RedirectAuthenticationRequest) authenticationRequest);
		}
		else {
			sendPost(request, response, (Saml2PostAuthenticationRequest) authenticationRequest);
		}
	}

	private void sendRedirect(HttpServletRequest request, HttpServletResponse response,
			Saml2RedirectAuthenticationRequest authenticationRequest) throws IOException {
		this.authenticationRequestRepository.saveAuthenticationRequest(authenticationRequest, request, response);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authenticationRequest.getAuthenticationRequestUri());
		addParameter(Saml2ParameterNames.SAML_REQUEST, authenticationRequest.getSamlRequest(), uriBuilder);
		addParameter(Saml2ParameterNames.RELAY_STATE, authenticationRequest.getRelayState(), uriBuilder);
		addParameter(Saml2ParameterNames.SIG_ALG, authenticationRequest.getSigAlg(), uriBuilder);
		addParameter(Saml2ParameterNames.SIGNATURE, authenticationRequest.getSignature(), uriBuilder);
		String redirectUrl = uriBuilder.build(true).toUriString();
		response.sendRedirect(redirectUrl);
	}

	private void addParameter(String name, String value, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(value)) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(value, StandardCharsets.ISO_8859_1));
		}
	}

	private void sendPost(HttpServletRequest request, HttpServletResponse response,
			Saml2PostAuthenticationRequest authenticationRequest) throws IOException {
		this.authenticationRequestRepository.saveAuthenticationRequest(authenticationRequest, request, response);
		String html = createSamlPostRequestFormData(authenticationRequest);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2PostAuthenticationRequest authenticationRequest) {
		String authenticationRequestUri = authenticationRequest.getAuthenticationRequestUri();
		String relayState = authenticationRequest.getRelayState();
		String samlRequest = authenticationRequest.getSamlRequest();
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
		html.append("        <meta http-equiv=\"Content-Security-Policy\" ")
				.append("content=\"script-src 'sha256-t+jmhLjs1ocvgaHBJsFcgznRk68d37TLtbI3NE9h7EU='\">\n");
		html.append("        <meta charset=\"utf-8\" />\n");
		html.append("    </head>\n");
		html.append("    <body>\n");
		html.append("        <noscript>\n");
		html.append("            <p>\n");
		html.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n");
		html.append("                you must press the Continue button once to proceed.\n");
		html.append("            </p>\n");
		html.append("        </noscript>\n");
		html.append("        \n");
		html.append("        <form action=\"");
		html.append(authenticationRequestUri);
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
		html.append("    <script>window.onload = () => document.forms[0].submit();</script>\n");
		html.append("</html>");
		return html.toString();
	}

}
