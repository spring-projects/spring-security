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
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.DefaultSaml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

/**
 * This {@code Filter} formulates a
 * <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">SAML 2.0 AuthnRequest</a> (line 1968)
 * and redirects to a configured asserting party.
 *
 * <p>
 * It supports the
 * <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">HTTP-Redirect</a> (line 520)
 * and
 * <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">HTTP-POST</a> (line 753)
 * bindings.
 *
 * <p>
 * By default, this {@code Filter} responds to authentication requests
 * at the {@code URI} {@code /oauth2/authorization/{registrationId}}.
 * The {@code URI} template variable {@code {registrationId}} represents the
 * {@link RelyingPartyRegistration#getRegistrationId() registration identifier} of the relying party
 * that is used for initiating the authentication request.
 *
 * @since 5.2
 * @author Filip Hanik
 * @author Josh Cummings
 */
public class Saml2WebSsoAuthenticationRequestFilter extends OncePerRequestFilter {

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
	private Saml2AuthenticationRequestFactory authenticationRequestFactory;
	private Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver = new DefaultSaml2AuthenticationRequestContextResolver();

	private RequestMatcher redirectMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}");

	/**
	 * Construct a {@link Saml2WebSsoAuthenticationRequestFilter} with the provided parameters
	 *
	 * @param relyingPartyRegistrationRepository a repository for relying party configurations
	 * @deprecated use the constructor that takes a {@link Saml2AuthenticationRequestFactory}
	 */
	@Deprecated
	public Saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		this(relyingPartyRegistrationRepository,
				new org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory());
	}

	/**
	 * Construct a {@link Saml2WebSsoAuthenticationRequestFilter} with the provided parameters
	 *
	 * @param relyingPartyRegistrationRepository a repository for relying party configurations
	 * @since 5.4
	 */
	public Saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
			Saml2AuthenticationRequestFactory authenticationRequestFactory) {
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		Assert.notNull(authenticationRequestFactory, "authenticationRequestFactory cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
		this.authenticationRequestFactory = authenticationRequestFactory;
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestFactory} for formulating the SAML 2.0 AuthnRequest
	 *
	 * @param authenticationRequestFactory the {@link Saml2AuthenticationRequestFactory} to use
	 * @deprecated use the constructor instead
	 */
	@Deprecated
	public void setAuthenticationRequestFactory(Saml2AuthenticationRequestFactory authenticationRequestFactory) {
		Assert.notNull(authenticationRequestFactory, "authenticationRequestFactory cannot be null");
		this.authenticationRequestFactory = authenticationRequestFactory;
	}

	/**
	 * Use the given {@link RequestMatcher} that activates this filter for a given request
	 *
	 * @param redirectMatcher the {@link RequestMatcher} to use
	 */
	public void setRedirectMatcher(RequestMatcher redirectMatcher) {
		Assert.notNull(redirectMatcher, "redirectMatcher cannot be null");
		this.redirectMatcher = redirectMatcher;
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestContextResolver} that creates a {@link Saml2AuthenticationRequestContext}
	 *
	 * @param authenticationRequestContextResolver the {@link Saml2AuthenticationRequestContextResolver} to use
	 * @since 5.4
	 */
	public void setAuthenticationRequestContextResolver(Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver) {
		Assert.notNull(authenticationRequestContextResolver, "authenticationRequestContextResolver cannot be null");
		this.authenticationRequestContextResolver = authenticationRequestContextResolver;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		MatchResult matcher = this.redirectMatcher.matcher(request);
		if (!matcher.isMatch()) {
			filterChain.doFilter(request, response);
			return;
		}

		String registrationId = matcher.getVariables().get("registrationId");
		RelyingPartyRegistration relyingParty =
				this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
		if (relyingParty == null) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		Saml2AuthenticationRequestContext context = authenticationRequestContextResolver.resolve(request, relyingParty);
		if (relyingParty.getAssertingPartyDetails().getSingleSignOnServiceBinding() == Saml2MessageBinding.REDIRECT) {
			sendRedirect(response, context);
		} else {
			sendPost(response, context);
		}
	}

	private void sendRedirect(HttpServletResponse response, Saml2AuthenticationRequestContext context)
			throws IOException {
		Saml2RedirectAuthenticationRequest authenticationRequest =
				this.authenticationRequestFactory.createRedirectAuthenticationRequest(context);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authenticationRequest.getAuthenticationRequestUri());
		addParameter("SAMLRequest", authenticationRequest.getSamlRequest(), uriBuilder);
		addParameter("RelayState", authenticationRequest.getRelayState(), uriBuilder);
		addParameter("SigAlg", authenticationRequest.getSigAlg(), uriBuilder);
		addParameter("Signature", authenticationRequest.getSignature(), uriBuilder);
		String redirectUrl = uriBuilder
				.build(true)
				.toUriString();
		response.sendRedirect(redirectUrl);
	}

	private void addParameter(String name, String value, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(value)) {
			builder.queryParam(
					UriUtils.encode(name, ISO_8859_1),
					UriUtils.encode(value, ISO_8859_1)
			);
		}
	}

	private void sendPost(HttpServletResponse response, Saml2AuthenticationRequestContext context)
			throws IOException {
		Saml2PostAuthenticationRequest authenticationRequest =
				this.authenticationRequestFactory.createPostAuthenticationRequest(context);
		String html = createSamlPostRequestFormData(authenticationRequest);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2PostAuthenticationRequest authenticationRequest) {
		String authenticationRequestUri = authenticationRequest.getAuthenticationRequestUri();
		String relayState = authenticationRequest.getRelayState();
		String samlRequest = authenticationRequest.getSamlRequest();
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
				.append("        <form action=\"").append(authenticationRequestUri).append("\" method=\"post\">\n")
				.append("            <div>\n")
				.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"")
				.append(HtmlUtils.htmlEscape(samlRequest))
				.append("\"/>\n");
		if (StringUtils.hasText(relayState)) {
			postHtml
					.append("                <input type=\"hidden\" name=\"RelayState\" value=\"")
					.append(HtmlUtils.htmlEscape(relayState))
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
				.append("</html>");
		return postHtml.toString();
	}
}
