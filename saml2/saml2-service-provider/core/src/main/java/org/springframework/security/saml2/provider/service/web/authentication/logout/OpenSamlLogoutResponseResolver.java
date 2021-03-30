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

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseMarshaller;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;
import org.springframework.util.Assert;

/**
 * A {@link Saml2LogoutRequestResolver} for resolving SAML 2.0 Logout Responses with
 * OpenSAML
 *
 * Note that there are {@link Saml2LogoutRequestResolver} implements that are targeted for
 * OpenSAML 3 and OpenSAML 4 via {@code OpenSaml3LogoutResponseResolver} and
 * {@code OpenSaml4LogoutResponseResolver}
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class OpenSamlLogoutResponseResolver implements Saml2LogoutResponseResolver {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	/**
	 * Construct a {@link OpenSamlLogoutResponseResolver} using the provided parameters
	 * @param relyingPartyRegistrationResolver the
	 * {@link RelyingPartyRegistrationResolver} for selecting the
	 * {@link RelyingPartyRegistration}
	 */
	public OpenSamlLogoutResponseResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Logout Response.
	 *
	 * By default, includes a {@code RelayState} based on the {@link HttpServletRequest}
	 * as well as the {@code Destination} and {@code Issuer} based on the
	 * {@link RelyingPartyRegistration} derived from the {@link Authentication}. The
	 * logout response is also marked as {@code SUCCESS}.
	 *
	 * The {@link Authentication} must be of type {@link Saml2Authentication} in order to
	 * look up the {@link RelyingPartyRegistration} that holds the signing key.
	 * @param request the HTTP request
	 * @param authentication the current principal details
	 * @return a builder, useful for overriding any aspects of the SAML 2.0 Logout Request
	 * that the resolver supplied
	 */
	@Override
	public OpenSamlLogoutResponseBuilder resolveLogoutResponse(HttpServletRequest request,
			Authentication authentication) {
		LogoutRequest logoutRequest = (LogoutRequest) request.getAttribute(LogoutRequest.class.getName());
		if (logoutRequest == null) {
			throw new Saml2Exception("Failed to find associated LogoutRequest");
		}
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				getRegistrationId(authentication));
		Assert.notNull(registration, "Failed to lookup RelyingPartyRegistration for request");
		return new OpenSamlLogoutResponseBuilder(registration)
				.destination(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation())
				.issuer(registration.getEntityId()).status(StatusCode.SUCCESS)
				.relayState(request.getParameter("RelayState")).inResponseTo(logoutRequest.getID());
	}

	private String getRegistrationId(Authentication authentication) {
		if (authentication instanceof Saml2Authentication) {
			return ((Saml2Authentication) authentication).getRelyingPartyRegistrationId();
		}
		return null;
	}

	/**
	 * A builder, useful for overriding any aspects of the SAML 2.0 Logout Response that
	 * the resolver supplied.
	 *
	 * The request returned from the {@link #logoutResponse()} method is signed and
	 * serialized. It will at minimum include an {@code ID}, though note that callers
	 * should include an {@code InResponseTo} and {@code IssueInstant}. For your
	 * convenience, {@link OpenSamlLogoutResponseResolver} also sets some default values.
	 *
	 * This builder is specifically handy for getting access to the underlying
	 * {@link LogoutResponse} to make changes before it gets signed and serialized
	 *
	 * @see OpenSamlLogoutResponseResolver#resolveLogoutResponse
	 */
	public static final class OpenSamlLogoutResponseBuilder
			implements Saml2LogoutResponseBuilder<OpenSamlLogoutResponseBuilder> {

		static {
			OpenSamlInitializationService.initialize();
		}

		private final LogoutResponseMarshaller marshaller;

		private final LogoutResponseBuilder logoutResponseBuilder;

		private final IssuerBuilder issuerBuilder;

		private final StatusBuilder statusBuilder;

		private final StatusCodeBuilder statusCodeBuilder;

		private final RelyingPartyRegistration registration;

		private final LogoutResponse logoutResponse;

		private String relayState;

		/**
		 * Construct a {@link OpenSamlLogoutResponseBuilder} using the provided parameters
		 * @param registration the {@link RelyingPartyRegistration} to use
		 */
		public OpenSamlLogoutResponseBuilder(RelyingPartyRegistration registration) {
			Assert.notNull(registration, "registration cannot be null");
			this.registration = registration;
			XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			this.marshaller = (LogoutResponseMarshaller) registry.getMarshallerFactory()
					.getMarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.marshaller, "logoutResponseMarshaller must be configured in OpenSAML");
			this.logoutResponseBuilder = (LogoutResponseBuilder) registry.getBuilderFactory()
					.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.logoutResponseBuilder, "logoutResponseBuilder must be configured in OpenSAML");
			this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
			this.statusBuilder = (StatusBuilder) registry.getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.statusBuilder, "statusBuilder must be configured in OpenSAML");
			this.statusCodeBuilder = (StatusCodeBuilder) registry.getBuilderFactory()
					.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.statusCodeBuilder, "statusCodeBuilder must be configured in OpenSAML");
			this.logoutResponse = this.logoutResponseBuilder.buildObject();
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutResponseBuilder inResponseTo(String inResponseTo) {
			this.logoutResponse.setInResponseTo(inResponseTo);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutResponseBuilder status(String status) {
			StatusCode code = this.statusCodeBuilder.buildObject();
			code.setValue(status);
			Status s = this.statusBuilder.buildObject();
			s.setStatusCode(code);
			this.logoutResponse.setStatus(s);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutResponseBuilder relayState(String relayState) {
			this.relayState = relayState;
			return this;
		}

		/**
		 * Mutate the {@link LogoutResponse} using the provided {@link Consumer}
		 * @param response the Logout Response {@link Consumer} to use
		 * @return the {@link OpenSamlLogoutResponseBuilder} for further customizations
		 */
		public OpenSamlLogoutResponseBuilder logoutResponse(Consumer<LogoutResponse> response) {
			response.accept(this.logoutResponse);
			return this;
		}

		private OpenSamlLogoutResponseBuilder destination(String destination) {
			this.logoutResponse.setDestination(destination);
			return this;
		}

		private OpenSamlLogoutResponseBuilder issuer(String issuer) {
			Issuer iss = this.issuerBuilder.buildObject();
			iss.setValue(issuer);
			this.logoutResponse.setIssuer(iss);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Saml2LogoutResponse logoutResponse() {
			Saml2LogoutResponse.Builder result = Saml2LogoutResponse.withRelyingPartyRegistration(this.registration);
			if (this.logoutResponse.getID() == null) {
				this.logoutResponse.setID("LR" + UUID.randomUUID());
			}
			if (this.registration.getAssertingPartyDetails()
					.getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
				String xml = serialize(OpenSamlSigningUtils.sign(this.logoutResponse, this.registration));
				return result.samlResponse(Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))).build();
			}
			else {
				String xml = serialize(this.logoutResponse);
				String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
				result.samlResponse(deflatedAndEncoded);
				QueryParametersPartial partial = OpenSamlSigningUtils.sign(this.registration).param("SAMLResponse",
						deflatedAndEncoded);
				if (this.relayState != null) {
					partial.param("RelayState", this.relayState);
				}
				return result.parameters((params) -> params.putAll(partial.parameters())).build();
			}
		}

		private String serialize(LogoutResponse logoutResponse) {
			try {
				Element element = this.marshaller.marshall(logoutResponse);
				return SerializeSupport.nodeToString(element);
			}
			catch (MarshallingException ex) {
				throw new Saml2Exception(ex);
			}
		}

	}

}
