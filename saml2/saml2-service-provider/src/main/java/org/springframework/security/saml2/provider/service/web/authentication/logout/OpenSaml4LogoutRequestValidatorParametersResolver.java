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

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An OpenSAML-based implementation of
 * {@link Saml2LogoutRequestValidatorParametersResolver}
 */
public final class OpenSaml4LogoutRequestValidatorParametersResolver
		implements Saml2LogoutRequestValidatorParametersResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final BaseOpenSamlLogoutRequestValidatorParametersResolver delegate;

	/**
	 * Constructs a {@link OpenSaml4LogoutRequestValidatorParametersResolver}
	 */
	public OpenSaml4LogoutRequestValidatorParametersResolver(RelyingPartyRegistrationRepository registrations) {
		Assert.notNull(registrations, "relyingPartyRegistrationRepository cannot be null");
		this.delegate = new BaseOpenSamlLogoutRequestValidatorParametersResolver(new OpenSaml4Template(),
				registrations);
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
		return this.delegate.resolve(request, authentication);
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
		this.delegate.setRequestMatcher(requestMatcher);
	}

}
