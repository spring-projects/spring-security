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
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * A {@link Saml2LogoutRequestResolver} for resolving SAML 2.0 Logout Requests with
 * OpenSAML
 *
 * Note that there are {@link Saml2LogoutRequestResolver} implements that are targeted for
 * OpenSAML 3 and OpenSAML 4 via {@code OpenSaml3LogoutRequestResolver} and
 * {@code OpenSaml4LogoutRequestResolver}
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class OpenSamlLogoutRequestResolver implements Saml2LogoutRequestResolver {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	/**
	 * Construct a {@link OpenSamlLogoutRequestResolver} using the provided parameters
	 * @param relyingPartyRegistrationResolver the
	 * {@link RelyingPartyRegistrationResolver} for selecting the
	 * {@link RelyingPartyRegistration}
	 */
	public OpenSamlLogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Logout Request.
	 *
	 * By default, includes a {@code NameID} based on the {@link Authentication} instance
	 * as well as the {@code Destination} and {@code Issuer} based on the
	 * {@link RelyingPartyRegistration} derived from the {@link Authentication}.
	 *
	 * The {@link Authentication} must be of type {@link Saml2Authentication} in order to
	 * look up the {@link RelyingPartyRegistration} that holds the signing key.
	 * @param request the HTTP request
	 * @param authentication the current principal details
	 * @return a builder, useful for overriding any aspects of the SAML 2.0 Logout Request
	 * that the resolver supplied
	 */
	@Override
	public OpenSamlLogoutRequestBuilder resolveLogoutRequest(HttpServletRequest request,
			Authentication authentication) {
		Assert.notNull(authentication, "Failed to lookup logged-in user for formulating LogoutRequest");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				getRegistrationId(authentication));
		Assert.notNull(registration, "Failed to lookup RelyingPartyRegistration for formulating LogoutRequest");
		return new OpenSamlLogoutRequestBuilder(registration)
				.destination(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation())
				.issuer(registration.getEntityId()).name(authentication.getName());
	}

	private String getRegistrationId(Authentication authentication) {
		if (authentication instanceof Saml2Authentication) {
			return ((Saml2Authentication) authentication).getRelyingPartyRegistrationId();
		}
		return null;
	}

	/**
	 * A builder, useful for overriding any aspects of the SAML 2.0 Logout Request that
	 * the resolver supplied.
	 *
	 * The request returned from the {@link #logoutRequest()} method is signed and
	 * serialized. It will at minimum include an {@code ID} and a {@code RelayState},
	 * though note that callers should also provide an {@code IssueInstant}. For your
	 * convenience, {@link OpenSamlLogoutRequestResolver} also sets some default values.
	 *
	 * This builder is specifically handy for getting access to the underlying
	 * {@link LogoutRequest} to make changes before it gets signed and serialized
	 *
	 * @see OpenSamlLogoutRequestResolver#resolveLogoutRequest
	 */
	public static final class OpenSamlLogoutRequestBuilder
			implements Saml2LogoutRequestBuilder<OpenSamlLogoutRequestBuilder> {

		static {
			OpenSamlInitializationService.initialize();
		}

		private final LogoutRequestMarshaller marshaller;

		private final IssuerBuilder issuerBuilder;

		private final NameIDBuilder nameIdBuilder;

		private final RelyingPartyRegistration registration;

		private final LogoutRequest logoutRequest;

		private String relayState;

		/**
		 * Construct a {@link OpenSamlLogoutRequestBuilder} using the provided parameters
		 * @param registration the {@link RelyingPartyRegistration} to use
		 */
		public OpenSamlLogoutRequestBuilder(RelyingPartyRegistration registration) {
			Assert.notNull(registration, "registration cannot be null");
			this.registration = registration;
			XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			this.marshaller = (LogoutRequestMarshaller) registry.getMarshallerFactory()
					.getMarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.marshaller, "logoutRequestMarshaller must be configured in OpenSAML");
			LogoutRequestBuilder logoutRequestBuilder = (LogoutRequestBuilder) registry.getBuilderFactory()
					.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
			Assert.notNull(logoutRequestBuilder, "logoutRequestBuilder must be configured in OpenSAML");
			this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
			this.nameIdBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.nameIdBuilder, "nameIdBuilder must be configured in OpenSAML");
			this.logoutRequest = logoutRequestBuilder.buildObject();
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutRequestBuilder name(String name) {
			NameID nameId = this.nameIdBuilder.buildObject();
			nameId.setValue(name);
			this.logoutRequest.setNameID(nameId);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutRequestBuilder relayState(String relayState) {
			this.relayState = relayState;
			return this;
		}

		/**
		 * Mutate the {@link LogoutRequest} using the provided {@link Consumer}
		 * @param request the Logout Request {@link Consumer} to use
		 * @return the {@link OpenSamlLogoutRequestBuilder} for further customizations
		 */
		public OpenSamlLogoutRequestBuilder logoutRequest(Consumer<LogoutRequest> request) {
			request.accept(this.logoutRequest);
			return this;
		}

		private OpenSamlLogoutRequestBuilder destination(String destination) {
			this.logoutRequest.setDestination(destination);
			return this;
		}

		private OpenSamlLogoutRequestBuilder issuer(String issuer) {
			Issuer iss = this.issuerBuilder.buildObject();
			iss.setValue(issuer);
			this.logoutRequest.setIssuer(iss);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Saml2LogoutRequest logoutRequest() {
			if (this.logoutRequest.getID() == null) {
				this.logoutRequest.setID("LR" + UUID.randomUUID());
			}
			if (this.relayState == null) {
				this.relayState = UUID.randomUUID().toString();
			}
			Saml2LogoutRequest.Builder result = Saml2LogoutRequest.withRelyingPartyRegistration(this.registration)
					.id(this.logoutRequest.getID());
			if (this.registration.getAssertingPartyDetails()
					.getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
				String xml = serialize(OpenSamlSigningUtils.sign(this.logoutRequest, this.registration));
				return result.samlRequest(Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))).build();
			}
			else {
				String xml = serialize(this.logoutRequest);
				String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
				result.samlRequest(deflatedAndEncoded);
				Map<String, String> parameters = OpenSamlSigningUtils.sign(this.registration)
						.param("SAMLRequest", deflatedAndEncoded).param("RelayState", this.relayState).parameters();
				return result.parameters((params) -> params.putAll(parameters)).build();
			}
		}

		private String serialize(LogoutRequest logoutRequest) {
			try {
				Element element = this.marshaller.marshall(logoutRequest);
				return SerializeSupport.nodeToString(element);
			}
			catch (MarshallingException ex) {
				throw new Saml2Exception(ex);
			}
		}

	}

}
