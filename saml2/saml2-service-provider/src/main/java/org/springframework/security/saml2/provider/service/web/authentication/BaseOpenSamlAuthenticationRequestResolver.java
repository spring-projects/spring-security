/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;
import org.springframework.util.Assert;

/**
 * For internal use only. Intended for consolidating common behavior related to minting a
 * SAML 2.0 Authn Request.
 */
class BaseOpenSamlAuthenticationRequestResolver implements Saml2AuthenticationRequestResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final OpenSamlOperations saml;

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private final AuthnRequestBuilder authnRequestBuilder;

	private final AuthnRequestMarshaller marshaller;

	private final IssuerBuilder issuerBuilder;

	private final NameIDBuilder nameIdBuilder;

	private final NameIDPolicyBuilder nameIdPolicyBuilder;

	private RequestMatcher requestMatcher = RequestMatchers.anyOf(
			new AntPathRequestMatcher(Saml2AuthenticationRequestResolver.DEFAULT_AUTHENTICATION_REQUEST_URI),
			new AntPathQueryRequestMatcher("/saml2/authenticate", "registrationId={registrationId}"));

	private Clock clock = Clock.systemUTC();

	private Converter<HttpServletRequest, String> relayStateResolver = (request) -> UUID.randomUUID().toString();

	private Consumer<AuthnRequestParameters> parametersConsumer = (parameters) -> {
	};

	/**
	 * Construct a {@link BaseOpenSamlAuthenticationRequestResolver} using the provided
	 * parameters
	 * @param relyingPartyRegistrationResolver a strategy for resolving the
	 * {@link RelyingPartyRegistration} from the {@link HttpServletRequest}
	 */
	BaseOpenSamlAuthenticationRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			OpenSamlOperations saml) {
		this.saml = saml;
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.marshaller = (AuthnRequestMarshaller) registry.getMarshallerFactory()
			.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.marshaller, "authnRequestMarshaller must be configured in OpenSAML");
		this.authnRequestBuilder = (AuthnRequestBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
			.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.authnRequestBuilder, "authnRequestBuilder must be configured in OpenSAML");
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
		this.nameIdBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.nameIdBuilder, "nameIdBuilder must be configured in OpenSAML");
		this.nameIdPolicyBuilder = (NameIDPolicyBuilder) registry.getBuilderFactory()
			.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.nameIdPolicyBuilder, "nameIdPolicyBuilder must be configured in OpenSAML");
	}

	void setClock(Clock clock) {
		this.clock = clock;
	}

	void setRelayStateResolver(Converter<HttpServletRequest, String> relayStateResolver) {
		this.relayStateResolver = relayStateResolver;
	}

	void setRequestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}

	void setParametersConsumer(Consumer<AuthnRequestParameters> parametersConsumer) {
		this.parametersConsumer = parametersConsumer;
	}

	@Override
	public <T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request) {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		String registrationId = result.getVariables().get("registrationId");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null) {
			return null;
		}
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		String entityId = uriResolver.resolve(registration.getEntityId());
		String assertionConsumerServiceLocation = uriResolver
			.resolve(registration.getAssertionConsumerServiceLocation());
		AuthnRequest authnRequest = this.authnRequestBuilder.buildObject();
		authnRequest.setForceAuthn(Boolean.FALSE);
		authnRequest.setIsPassive(Boolean.FALSE);
		authnRequest.setProtocolBinding(registration.getAssertionConsumerServiceBinding().getUrn());
		Issuer iss = this.issuerBuilder.buildObject();
		iss.setValue(entityId);
		authnRequest.setIssuer(iss);
		authnRequest.setDestination(registration.getAssertingPartyMetadata().getSingleSignOnServiceLocation());
		authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceLocation);
		if (registration.getNameIdFormat() != null) {
			NameIDPolicy nameIdPolicy = this.nameIdPolicyBuilder.buildObject();
			nameIdPolicy.setFormat(registration.getNameIdFormat());
			authnRequest.setNameIDPolicy(nameIdPolicy);
		}
		authnRequest.setIssueInstant(Instant.now(this.clock));
		this.parametersConsumer.accept(new AuthnRequestParameters(request, registration, authnRequest));
		if (authnRequest.getID() == null) {
			authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		}
		String relayState = this.relayStateResolver.convert(request);
		Saml2MessageBinding binding = registration.getAssertingPartyMetadata().getSingleSignOnServiceBinding();
		if (binding == Saml2MessageBinding.POST) {
			if (registration.getAssertingPartyMetadata().getWantAuthnRequestsSigned()
					|| registration.isAuthnRequestsSigned()) {
				this.saml.withSigningKeys(registration.getSigningX509Credentials())
					.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
					.sign(authnRequest);
			}
			String xml = serialize(authnRequest);
			String encoded = Saml2Utils.withDecoded(xml).encode();
			return (T) Saml2PostAuthenticationRequest.withRelyingPartyRegistration(registration)
				.samlRequest(encoded)
				.relayState(relayState)
				.id(authnRequest.getID())
				.build();
		}
		else {
			String xml = serialize(authnRequest);
			String deflatedAndEncoded = Saml2Utils.withDecoded(xml).deflate(true).encode();
			Saml2RedirectAuthenticationRequest.Builder builder = Saml2RedirectAuthenticationRequest
				.withRelyingPartyRegistration(registration)
				.samlRequest(deflatedAndEncoded)
				.relayState(relayState)
				.id(authnRequest.getID());
			if (registration.getAssertingPartyMetadata().getWantAuthnRequestsSigned()
					|| registration.isAuthnRequestsSigned()) {
				Map<String, String> signingParameters = new HashMap<>();
				signingParameters.put(Saml2ParameterNames.SAML_REQUEST, deflatedAndEncoded);
				if (relayState != null) {
					signingParameters.put(Saml2ParameterNames.RELAY_STATE, relayState);
				}
				Map<String, String> query = this.saml.withSigningKeys(registration.getSigningX509Credentials())
					.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
					.sign(signingParameters);
				builder.sigAlg(query.get(Saml2ParameterNames.SIG_ALG))
					.signature(query.get(Saml2ParameterNames.SIGNATURE));
			}
			return (T) builder.build();
		}
	}

	private String serialize(AuthnRequest authnRequest) {
		return this.saml.serialize(authnRequest).serialize();
	}

	private static final class AntPathQueryRequestMatcher implements RequestMatcher {

		private final RequestMatcher matcher;

		AntPathQueryRequestMatcher(String path, String... params) {
			List<RequestMatcher> matchers = new ArrayList<>();
			matchers.add(new AntPathRequestMatcher(path));
			for (String param : params) {
				String[] parts = param.split("=");
				if (parts.length == 1) {
					matchers.add(new ParameterRequestMatcher(parts[0]));
				}
				else {
					matchers.add(new ParameterRequestMatcher(parts[0], parts[1]));
				}
			}
			this.matcher = new AndRequestMatcher(matchers);
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return matcher(request).isMatch();
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return this.matcher.matcher(request);
		}

	}

	static final class AuthnRequestParameters {

		private final HttpServletRequest request;

		private final RelyingPartyRegistration registration;

		private final AuthnRequest authnRequest;

		AuthnRequestParameters(HttpServletRequest request, RelyingPartyRegistration registration,
				AuthnRequest authnRequest) {
			this.request = request;
			this.registration = registration;
			this.authnRequest = authnRequest;
		}

		HttpServletRequest getRequest() {
			return this.request;
		}

		RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

		AuthnRequest getAuthnRequest() {
			return this.authnRequest;
		}

	}

}
