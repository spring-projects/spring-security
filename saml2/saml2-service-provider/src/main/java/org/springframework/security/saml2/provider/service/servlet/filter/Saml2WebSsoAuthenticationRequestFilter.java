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

package org.springframework.security.saml2.provider.service.servlet.filter;

import java.io.IOException;
import java.util.function.Function;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationRequestFilter extends OncePerRequestFilter {

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
	private RequestMatcher redirectMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}");
	private Saml2AuthenticationRequestFactory authenticationRequestFactory = new OpenSamlAuthenticationRequestFactory();

	public Saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
	}

	public void setAuthenticationRequestFactory(Saml2AuthenticationRequestFactory authenticationRequestFactory) {
		Assert.notNull(authenticationRequestFactory, "authenticationRequestFactory cannot be null");
		this.authenticationRequestFactory = authenticationRequestFactory;
	}

	public void setRedirectMatcher(RequestMatcher redirectMatcher) {
		Assert.notNull(redirectMatcher, "redirectMatcher cannot be null");
		this.redirectMatcher = redirectMatcher;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		MatchResult matcher = this.redirectMatcher.matcher(request);
		if (!matcher.isMatch()) {
			filterChain.doFilter(request, response);
			return;
		}

		String registrationId = matcher.getVariables().get("registrationId");
		RelyingPartyRegistration relyingParty = this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
		if (relyingParty == null) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(format("Creating SAML2 SP Authentication Request for IDP[%s]", relyingParty.getRegistrationId()));
		}
		Saml2AuthenticationRequestContext authnRequestCtx = createRedirectAuthenticationRequestContext(relyingParty, request);
		if (relyingParty.getProviderDetails().getBinding() == Saml2MessageBinding.REDIRECT) {
			sendRedirect(response, authnRequestCtx);
		}
		else {
			sendPost(response, authnRequestCtx);
		}
	}

	private void sendRedirect(HttpServletResponse response, Saml2AuthenticationRequestContext authnRequestCtx)
			throws IOException {
		String redirectUrl = createSamlRequestRedirectUrl(authnRequestCtx);
		response.sendRedirect(redirectUrl);
	}

	private void sendPost(HttpServletResponse response, Saml2AuthenticationRequestContext authnRequestCtx)
			throws IOException {
		Saml2PostAuthenticationRequest authNData =
				this.authenticationRequestFactory.createPostAuthenticationRequest(authnRequestCtx);
		String html = createSamlPostRequestFormData(authNData);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlRequestRedirectUrl(Saml2AuthenticationRequestContext authnRequestCtx) {

		Saml2RedirectAuthenticationRequest authNData =
				this.authenticationRequestFactory.createRedirectAuthenticationRequest(authnRequestCtx);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(authNData.getAuthenticationRequestUri());
		addParameter("SAMLRequest", authNData.getSamlRequest(), uriBuilder);
		addParameter("RelayState", authNData.getRelayState(), uriBuilder);
		addParameter("SigAlg", authNData.getSigAlg(), uriBuilder);
		addParameter("Signature", authNData.getSignature(), uriBuilder);
		return uriBuilder
				.build(true)
				.toUriString();
	}

	private void addParameter(String name, String value, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (hasText(value)) {
			builder.queryParam(
					UriUtils.encode(name, ISO_8859_1),
					UriUtils.encode(value, ISO_8859_1)
			);
		}
	}

	private Saml2AuthenticationRequestContext createRedirectAuthenticationRequestContext(
			RelyingPartyRegistration relyingParty,
			HttpServletRequest request) {
		String applicationUri = Saml2ServletUtils.getApplicationUri(request);
		Function<String, String> resolver = templateResolver(applicationUri, relyingParty);
		String localSpEntityId = resolver.apply(relyingParty.getLocalEntityIdTemplate());
		String assertionConsumerServiceUrl = resolver.apply(relyingParty.getAssertionConsumerServiceUrlTemplate());
		return Saml2AuthenticationRequestContext.builder()
				.issuer(localSpEntityId)
				.relyingPartyRegistration(relyingParty)
				.assertionConsumerServiceUrl(assertionConsumerServiceUrl)
				.relayState(request.getParameter("RelayState"))
				.build();
	}

	private Function<String, String> templateResolver(String applicationUri, RelyingPartyRegistration relyingParty) {
		return template -> Saml2ServletUtils.resolveUrlTemplate(template, applicationUri, relyingParty);
	}

	private String htmlEscape(String value) {
		if (hasText(value)) {
			return HtmlUtils.htmlEscape(value);
		}
		return value;
	}

	private String createSamlPostRequestFormData(Saml2PostAuthenticationRequest request) {
		String destination = request.getAuthenticationRequestUri();
		String relayState = htmlEscape(request.getRelayState());
		String samlRequest = htmlEscape(request.getSamlRequest());
		StringBuilder postHtml = new StringBuilder()
				.append("<!DOCTYPE html>\n")
				.append("<html>\n")
				.append("    <head>\n")
				.append("        <meta charset=\"utf-8\" />\n")
				.append("    </head>\n")
				.append("    <body onload=\"document.forms[0].submit()\">\n")
				.append("        <noscript>\n")
				.append("            <p>\n")
				.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n")
				.append("                you must press the Continue button once to proceed.\n")
				.append("            </p>\n")
				.append("        </noscript>\n")
				.append("        \n")
				.append("        <form action=\"").append(destination).append("\" method=\"post\">\n")
				.append("            <div>\n")
				.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"")
				.append(samlRequest)
				.append("\"/>\n")
				;
		if (hasText(relayState)) {
			postHtml
					.append("                <input type=\"hidden\" name=\"RelayState\" value=\"")
					.append(relayState)
					.append("\"/>\n");
		}
		postHtml
				.append("            </div>\n")
				.append("            <noscript>\n")
				.append("                <div>\n")
				.append("                    <input type=\"submit\" value=\"Continue\"/>\n")
				.append("                </div>\n")
				.append("            </noscript>\n")
				.append("        </form>\n")
				.append("        \n")
				.append("    </body>\n")
				.append("</html>")
		;
		return postHtml.toString();
	}
}
