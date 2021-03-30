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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlVerificationUtils.VerifierPartial;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

/**
 * A {@link LogoutHandler} that handles SAML 2.0 Logout Responses received from a SAML 2.0
 * Asserting Party.
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class OpenSamlLogoutResponseHandler implements LogoutHandler {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private final ParserPool parserPool;

	private final LogoutResponseUnmarshaller unmarshaller;

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	/**
	 * Constructs a {@link OpenSamlLogoutResponseHandler} from the provided parameters
	 * @param relyingPartyRegistrationResolver the
	 * {@link RelyingPartyRegistrationResolver} from which to derive the
	 * {@link RelyingPartyRegistration}
	 */
	public OpenSamlLogoutResponseHandler(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutResponseUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * Processes the SAML 2.0 Logout Response received from the SAML 2.0 Asserting Party.
	 *
	 * By default, verifies the signature, validates the issuer, destination, and status.
	 *
	 * If any processing step fails, a {@link Saml2Exception} is thrown, stopping the
	 * logout process
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param authentication the current principal details
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String serialized = request.getParameter("SAMLResponse");
		Assert.notNull(serialized, "SAMLResponse cannot be null");
		byte[] b = Saml2Utils.samlDecode(serialized);
		serialized = inflateIfRequired(request, b);
		Saml2LogoutRequest logoutRequest = this.logoutRequestRepository.removeLogoutRequest(request, response);
		if (logoutRequest == null) {
			throw new Saml2Exception("Failed to find associated LogoutRequest");
		}
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				logoutRequest.getRelyingPartyRegistrationId());
		LogoutResponse logoutResponse = parse(serialized);
		Saml2ResponseValidatorResult result = verifySignature(request, logoutResponse, registration)
				.concat(validateRequest(logoutResponse, registration))
				.concat(validateLogoutRequest(logoutResponse, logoutRequest.getId()));
		if (result.hasErrors()) {
			throw new Saml2Exception("Failed to validate LogoutResponse: " + result.getErrors().iterator().next());
		}
	}

	/**
	 * Use this {@link Saml2LogoutRequestRepository} for looking up the associated logout
	 * request.
	 * @param logoutRequestRepository the {@link Saml2LogoutRequestRepository} to use
	 */
	public void setLogoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
		Assert.notNull(logoutRequestRepository, "logoutRequestRepository cannot be null");
		this.logoutRequestRepository = logoutRequestRepository;
	}

	private String inflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return Saml2Utils.samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private LogoutResponse parse(String response) throws Saml2Exception {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutResponse", ex);
		}
	}

	private Saml2ResponseValidatorResult verifySignature(HttpServletRequest request, LogoutResponse response,
			RelyingPartyRegistration registration) {
		VerifierPartial partial = OpenSamlVerificationUtils.verifySignature(response, registration);
		if (response.isSigned()) {
			return partial.post(response.getSignature());
		}
		return partial.redirect(request, "SAMLResponse");
	}

	private Saml2ResponseValidatorResult validateRequest(LogoutResponse response,
			RelyingPartyRegistration registration) {
		Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
		return result.concat(validateIssuer(response, registration)).concat(validateDestination(response, registration))
				.concat(validateStatus(response));
	}

	private Saml2ResponseValidatorResult validateIssuer(LogoutResponse response,
			RelyingPartyRegistration registration) {
		if (response.getIssuer() == null) {
			return Saml2ResponseValidatorResult
					.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
		}
		String issuer = response.getIssuer().getValue();
		if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
			return Saml2ResponseValidatorResult.failure(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private Saml2ResponseValidatorResult validateDestination(LogoutResponse response,
			RelyingPartyRegistration registration) {
		if (response.getDestination() == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to find destination in LogoutResponse"));
		}
		String destination = response.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceResponseLocation())) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to match destination to configured destination"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private Saml2ResponseValidatorResult validateStatus(LogoutResponse response) {
		if (response.getStatus() == null) {
			return Saml2ResponseValidatorResult.success();
		}
		if (response.getStatus().getStatusCode() == null) {
			return Saml2ResponseValidatorResult.success();
		}
		if (StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
			return Saml2ResponseValidatorResult.success();
		}
		if (StatusCode.PARTIAL_LOGOUT.equals(response.getStatus().getStatusCode().getValue())) {
			return Saml2ResponseValidatorResult.success();
		}
		return Saml2ResponseValidatorResult
				.failure(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response indicated logout failed"));
	}

	private Saml2ResponseValidatorResult validateLogoutRequest(LogoutResponse response, String id) {
		if (response.getInResponseTo() == null) {
			return Saml2ResponseValidatorResult.success();
		}
		if (response.getInResponseTo().equals(id)) {
			return Saml2ResponseValidatorResult.success();
		}
		return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
				"LogoutResponse InResponseTo doesn't match ID of associated LogoutRequest"));
	}

}
