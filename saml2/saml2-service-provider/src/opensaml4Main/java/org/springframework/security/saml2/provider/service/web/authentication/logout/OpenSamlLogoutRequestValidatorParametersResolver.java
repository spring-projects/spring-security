/*
 * Copyright 2002-2023 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An OpenSAML-based implementation of
 * {@link Saml2LogoutRequestValidatorParametersResolver}
 *
 * @deprecated Please use a version-specific
 * {@link Saml2LogoutRequestValidatorParametersResolver} such as
 * {@code OpenSaml4LogoutRequestValidatorParametersResolver}
 */
@Deprecated
public final class OpenSamlLogoutRequestValidatorParametersResolver
		implements Saml2LogoutRequestValidatorParametersResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private RequestMatcher requestMatcher = new OrRequestMatcher(
			new AntPathRequestMatcher("/logout/saml2/slo/{registrationId}"),
			new AntPathRequestMatcher("/logout/saml2/slo"));

	private final OpenSamlOperations saml = new OpenSaml4Template();

	private final RelyingPartyRegistrationRepository registrations;

	private final XMLObjectProviderRegistry registry;

	private final LogoutRequestUnmarshaller unmarshaller;

	/**
	 * Constructs a {@link OpenSamlLogoutRequestValidatorParametersResolver}
	 */
	public OpenSamlLogoutRequestValidatorParametersResolver(RelyingPartyRegistrationRepository registrations) {
		Assert.notNull(registrations, "relyingPartyRegistrationRepository cannot be null");
		this.registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.unmarshaller = (LogoutRequestUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
			.getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
		this.registrations = registrations;
	}

	/**
	 * Construct the parameters necessary for validating an asserting party's
	 * {@code <saml2:LogoutRequest>} based on the given {@link HttpServletRequest}
	 *
	 * <p>
	 * Uses the configured {@link RequestMatcher} to identify the processing request,
	 * including looking for any indicated {@code registrationId}.
	 *
	 * <p>
	 * If a {@code registrationId} is found in the request, it will attempt to use that,
	 * erroring if no {@link RelyingPartyRegistration} is found.
	 *
	 * <p>
	 * If no {@code registrationId} is found in the request, it will look for a currently
	 * logged-in user and use the associated {@code registrationId}.
	 *
	 * <p>
	 * In the event that neither the URL nor any logged in user could determine a
	 * {@code registrationId}, this code then will try and derive a
	 * {@link RelyingPartyRegistration} given the {@code <saml2:LogoutRequest>}'s
	 * {@code Issuer} value.
	 * @param request the HTTP request
	 * @return a {@link Saml2LogoutRequestValidatorParameters} instance, or {@code null}
	 * if one could not be resolved
	 * @throws Saml2AuthenticationException if the {@link RequestMatcher} specifies a
	 * non-existent {@code registrationId}
	 */
	@Override
	public Saml2LogoutRequestValidatorParameters resolve(HttpServletRequest request, Authentication authentication) {
		if (request.getParameter(Saml2ParameterNames.SAML_REQUEST) == null) {
			return null;
		}
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		String registrationId = getRegistrationId(result, authentication);
		if (registrationId == null) {
			return logoutRequestByEntityId(request, authentication);
		}
		return logoutRequestById(request, authentication, registrationId);
	}

	/**
	 * The request matcher to use to identify a request to process a
	 * {@code <saml2:LogoutRequest>}. By default, checks for {@code /logout/saml2/slo} and
	 * {@code /logout/saml2/slo/{registrationId}}.
	 *
	 * <p>
	 * Generally speaking, the URL does not need to have a {@code registrationId} in it
	 * since either it can be looked up from the active logged in user or it can be
	 * derived through the {@code Issuer} in the {@code <saml2:LogoutRequest>}.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	private String getRegistrationId(RequestMatcher.MatchResult result, Authentication authentication) {
		String registrationId = result.getVariables().get("registrationId");
		if (registrationId != null) {
			return registrationId;
		}
		if (authentication == null) {
			return null;
		}
		if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal) {
			return principal.getRelyingPartyRegistrationId();
		}
		return null;
	}

	private Saml2LogoutRequestValidatorParameters logoutRequestById(HttpServletRequest request,
			Authentication authentication, String registrationId) {
		RelyingPartyRegistration registration = this.registrations.findByRegistrationId(registrationId);
		if (registration == null) {
			throw new Saml2AuthenticationException(
					new Saml2Error(Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND, "registration not found"),
					"registration not found");
		}
		return logoutRequestByRegistration(request, registration, authentication);
	}

	private Saml2LogoutRequestValidatorParameters logoutRequestByEntityId(HttpServletRequest request,
			Authentication authentication) {
		String serialized = request.getParameter(Saml2ParameterNames.SAML_REQUEST);
		LogoutRequest logoutRequest = this.saml
			.deserialize(org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2Utils
				.withEncoded(serialized)
				.inflate(HttpMethod.GET.matches(request.getMethod()))
				.decode());
		String issuer = logoutRequest.getIssuer().getValue();
		RelyingPartyRegistration registration = this.registrations.findUniqueByAssertingPartyEntityId(issuer);
		return logoutRequestByRegistration(request, registration, authentication);
	}

	private Saml2LogoutRequestValidatorParameters logoutRequestByRegistration(HttpServletRequest request,
			RelyingPartyRegistration registration, Authentication authentication) {
		if (registration == null) {
			return null;
		}
		Saml2MessageBinding saml2MessageBinding = Saml2MessageBindingUtils.resolveBinding(request);
		registration = fromRequest(request, registration);
		String serialized = request.getParameter(Saml2ParameterNames.SAML_REQUEST);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
			.samlRequest(serialized)
			.relayState(request.getParameter(Saml2ParameterNames.RELAY_STATE))
			.binding(saml2MessageBinding)
			.location(registration.getSingleLogoutServiceLocation())
			.parameters((params) -> params.put(Saml2ParameterNames.SIG_ALG,
					request.getParameter(Saml2ParameterNames.SIG_ALG)))
			.parameters((params) -> params.put(Saml2ParameterNames.SIGNATURE,
					request.getParameter(Saml2ParameterNames.SIGNATURE)))
			.parametersQuery((params) -> request.getQueryString())
			.build();
		return new Saml2LogoutRequestValidatorParameters(logoutRequest, registration, authentication);
	}

	private RelyingPartyRegistration fromRequest(HttpServletRequest request, RelyingPartyRegistration registration) {
		RelyingPartyRegistrationPlaceholderResolvers.UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers
			.uriResolver(request, registration);
		String entityId = uriResolver.resolve(registration.getEntityId());
		String logoutLocation = uriResolver.resolve(registration.getSingleLogoutServiceLocation());
		String logoutResponseLocation = uriResolver.resolve(registration.getSingleLogoutServiceResponseLocation());
		return registration.mutate()
			.entityId(entityId)
			.singleLogoutServiceLocation(logoutLocation)
			.singleLogoutServiceResponseLocation(logoutResponseLocation)
			.build();
	}

}
