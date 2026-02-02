/*
 * Copyright 2004-present the original author or authors.
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
import java.util.Objects;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A filter for handling logout requests in the form of a &lt;saml2:LogoutRequest&gt; sent
 * from the asserting party.
 *
 * @author Josh Cummings
 * @since 5.6
 * @see Saml2LogoutRequestValidator
 */
public final class Saml2LogoutRequestFilter extends OncePerRequestFilter {

	private final Log logger = LogFactory.getLog(getClass());

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private final Saml2LogoutRequestValidatorParametersResolver logoutRequestResolver;

	private final Saml2LogoutRequestValidator logoutRequestValidator;

	private final Saml2LogoutResponseResolver logoutResponseResolver;

	private final LogoutHandler handler;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public Saml2LogoutRequestFilter(Saml2LogoutRequestValidatorParametersResolver logoutRequestResolver,
			Saml2LogoutRequestValidator logoutRequestValidator, Saml2LogoutResponseResolver logoutResponseResolver,
			LogoutHandler... handlers) {
		this.logoutRequestResolver = logoutRequestResolver;
		this.logoutRequestValidator = logoutRequestValidator;
		this.logoutResponseResolver = logoutResponseResolver;
		this.handler = new CompositeLogoutHandler(handlers);
	}

	/**
	 * Constructs a {@link Saml2LogoutResponseFilter} for accepting SAML 2.0 Logout
	 * Requests from the asserting party
	 * @param relyingPartyRegistrationResolver the strategy for resolving a
	 * {@link RelyingPartyRegistration}
	 * @param logoutRequestValidator the SAML 2.0 Logout Request authenticator
	 * @param logoutResponseResolver the strategy for creating a SAML 2.0 Logout Response
	 * @param handlers the actions that perform logout
	 */
	public Saml2LogoutRequestFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			Saml2LogoutRequestValidator logoutRequestValidator, Saml2LogoutResponseResolver logoutResponseResolver,
			LogoutHandler... handlers) {
		this.logoutRequestResolver = new Saml2AssertingPartyLogoutRequestResolver(relyingPartyRegistrationResolver);
		this.logoutRequestValidator = logoutRequestValidator;
		this.logoutResponseResolver = logoutResponseResolver;
		this.handler = new CompositeLogoutHandler(handlers);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		Saml2LogoutRequestValidatorParameters parameters;
		try {
			parameters = this.logoutRequestResolver.resolve(request, authentication);
		}
		catch (Saml2AuthenticationException ex) {
			this.logger.trace("Did not process logout request since failed to find requested RelyingPartyRegistration");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		if (parameters == null) {
			chain.doFilter(request, response);
			return;
		}

		try {
			validateLogoutRequest(request, parameters);
		}
		catch (Saml2AuthenticationException ex) {
			Saml2LogoutResponse errorLogoutResponse = this.logoutResponseResolver.resolve(request, authentication, ex);
			if (errorLogoutResponse == null) {
				this.logger.trace(LogMessage.format(
						"Returning error since no error logout response could be generated: %s", ex.getSaml2Error()));
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}

			sendLogoutResponse(request, response, errorLogoutResponse);
			return;
		}

		this.handler.logout(request, response, authentication);
		Saml2LogoutResponse logoutResponse = this.logoutResponseResolver.resolve(request, authentication);
		if (logoutResponse == null) {
			this.logger.trace("Returning error since no logout response generated");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		sendLogoutResponse(request, response, logoutResponse);
	}

	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		Assert.isInstanceOf(Saml2AssertingPartyLogoutRequestResolver.class, this.logoutRequestResolver,
				"saml2LogoutRequestResolver and logoutRequestMatcher cannot both be set. Please set the request matcher in the saml2LogoutRequestResolver itself.");
		((Saml2AssertingPartyLogoutRequestResolver) this.logoutRequestResolver)
			.setLogoutRequestMatcher(logoutRequestMatcher);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	private void validateLogoutRequest(HttpServletRequest request, Saml2LogoutRequestValidatorParameters parameters) {
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		if (registration.getSingleLogoutServiceLocation() == null) {
			this.logger.trace(
					"Did not process logout request since RelyingPartyRegistration has not been configured with a logout request endpoint");
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"RelyingPartyRegistration has not been configured with a logout request endpoint"));
		}

		Saml2MessageBinding saml2MessageBinding = Saml2MessageBindingUtils.resolveBinding(request);
		if (!registration.getSingleLogoutServiceBindings().contains(saml2MessageBinding)) {
			this.logger.trace("Did not process logout request since used incorrect binding");
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST, "Logout request used invalid binding"));
		}

		Saml2LogoutValidatorResult result = this.logoutRequestValidator.validate(parameters);
		if (result.hasErrors()) {
			this.logger.debug(LogMessage.format("Failed to validate LogoutRequest: %s", result.getErrors()));
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST, "Failed to validate the logout request"));
		}
	}

	private void sendLogoutResponse(HttpServletRequest request, HttpServletResponse response,
			Saml2LogoutResponse logoutResponse) throws IOException {
		if (logoutResponse.getBinding() == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, logoutResponse);
		}
		else {
			doPost(response, logoutResponse);
		}
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response,
			Saml2LogoutResponse logoutResponse) throws IOException {
		String location = logoutResponse.getResponseLocation();
		String query = logoutResponse.getParametersQuery();
		Assert.notNull(query, "logout response must have a parameters query when using redirect binding");
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location).query(query);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void doPost(HttpServletResponse response, Saml2LogoutResponse logoutResponse) throws IOException {
		String location = logoutResponse.getResponseLocation();
		String saml = logoutResponse.getSamlResponse();
		String relayState = logoutResponse.getRelayState();
		String html = createSamlPostRequestFormData(location, saml, relayState);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(String location, String saml, @Nullable String relayState) {
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
		html.append("        <meta http-equiv=\"Content-Security-Policy\" ")
			.append("content=\"script-src 'sha256-oZhLbc2kO8b8oaYLrUc7uye1MgVKMyLtPqWR4WtKF+c='\">\n");
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
		html.append(location);
		html.append("\" method=\"post\">\n");
		html.append("            <div>\n");
		html.append("                <input type=\"hidden\" name=\"SAMLResponse\" value=\"");
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
		html.append("        <script>window.onload = function() { document.forms[0].submit(); }</script>\n");
		html.append("    </body>\n");
		html.append("</html>");
		return html.toString();
	}

	private static class Saml2AssertingPartyLogoutRequestResolver
			implements Saml2LogoutRequestValidatorParametersResolver {

		private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

		private RequestMatcher logoutRequestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher("/logout/saml2/slo");

		Saml2AssertingPartyLogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		}

		@Override
		public @Nullable Saml2LogoutRequestValidatorParameters resolve(HttpServletRequest request,
				@Nullable Authentication authentication) {
			String serialized = request.getParameter(Saml2ParameterNames.SAML_REQUEST);
			if (serialized == null) {
				return null;
			}
			RequestMatcher.MatchResult result = this.logoutRequestMatcher.matcher(request);
			if (!result.isMatch()) {
				return null;
			}
			String registrationId = getRegistrationId(result, authentication);
			RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
					registrationId);
			if (registration == null) {
				throw new Saml2AuthenticationException(
						Saml2Error.relyingPartyRegistrationNotFound("registration not found"));
			}
			UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
			String entityId = uriResolver.resolve(registration.getEntityId());
			entityId = Objects.requireNonNull(entityId);
			String logoutLocation = uriResolver.resolve(registration.getSingleLogoutServiceLocation());
			String logoutResponseLocation = uriResolver.resolve(registration.getSingleLogoutServiceResponseLocation());
			registration = registration.mutate()
				.entityId(entityId)
				.singleLogoutServiceLocation(logoutLocation)
				.singleLogoutServiceResponseLocation(logoutResponseLocation)
				.build();
			Saml2MessageBinding saml2MessageBinding = Saml2MessageBindingUtils.resolveBinding(request);
			Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(serialized)
				.relayState(request.getParameter(Saml2ParameterNames.RELAY_STATE))
				.binding(saml2MessageBinding)
				.parameters((params) -> params.put(Saml2ParameterNames.SIG_ALG,
						request.getParameter(Saml2ParameterNames.SIG_ALG)))
				.parameters((params) -> params.put(Saml2ParameterNames.SIGNATURE,
						request.getParameter(Saml2ParameterNames.SIGNATURE)))
				.parametersQuery((params) -> request.getQueryString())
				.build();
			return new Saml2LogoutRequestValidatorParameters(logoutRequest, registration, authentication);
		}

		void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
			Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
			this.logoutRequestMatcher = logoutRequestMatcher;
		}

		private @Nullable String getRegistrationId(RequestMatcher.MatchResult result,
				@Nullable Authentication authentication) {
			String registrationId = result.getVariables().get("registrationId");
			if (registrationId != null) {
				return registrationId;
			}
			if (authentication == null) {
				return null;
			}
			if (authentication instanceof Saml2AssertionAuthentication saml2) {
				return saml2.getRelyingPartyRegistrationId();
			}
			if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal saml2) {
				return saml2.getRelyingPartyRegistrationId();
			}
			return null;
		}

	}

}
