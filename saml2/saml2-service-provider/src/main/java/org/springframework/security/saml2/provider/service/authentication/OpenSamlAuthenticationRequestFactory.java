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

package org.springframework.security.saml2.provider.service.authentication;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.security.impl.SAMLMetadataSignatureSigningParametersResolver;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Element;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest.Builder;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * @since 5.2
 */
public class OpenSamlAuthenticationRequestFactory implements Saml2AuthenticationRequestFactory {

	static {
		OpenSamlInitializationService.initialize();
	}

	private Clock clock = Clock.systemUTC();

	private AuthnRequestMarshaller marshaller;

	private AuthnRequestBuilder authnRequestBuilder;

	private IssuerBuilder issuerBuilder;

	private Converter<Saml2AuthenticationRequestContext, String> protocolBindingResolver = (context) -> {
		if (context == null) {
			return SAMLConstants.SAML2_POST_BINDING_URI;
		}
		return context.getRelyingPartyRegistration().getAssertionConsumerServiceBinding().getUrn();
	};

	private Converter<Saml2AuthenticationRequestContext, AuthnRequest> authenticationRequestContextConverter = this::createAuthnRequest;

	/**
	 * Creates an {@link OpenSamlAuthenticationRequestFactory}
	 */
	public OpenSamlAuthenticationRequestFactory() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.marshaller = (AuthnRequestMarshaller) registry.getMarshallerFactory()
				.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
		this.authnRequestBuilder = (AuthnRequestBuilder) registry.getBuilderFactory()
				.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	}

	@Override
	@Deprecated
	public String createAuthenticationRequest(Saml2AuthenticationRequest request) {
		AuthnRequest authnRequest = createAuthnRequest(request.getIssuer(), request.getDestination(),
				request.getAssertionConsumerServiceUrl(), this.protocolBindingResolver.convert(null));
		for (org.springframework.security.saml2.credentials.Saml2X509Credential credential : request.getCredentials()) {
			if (credential.isSigningCredential()) {
				X509Certificate certificate = credential.getCertificate();
				PrivateKey privateKey = credential.getPrivateKey();
				BasicCredential cred = CredentialSupport.getSimpleCredential(certificate, privateKey);
				cred.setEntityId(request.getIssuer());
				cred.setUsageType(UsageType.SIGNING);
				SignatureSigningParameters parameters = new SignatureSigningParameters();
				parameters.setSigningCredential(cred);
				parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
				parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
				parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
				return serialize(sign(authnRequest, parameters));
			}
		}
		throw new IllegalArgumentException("No signing credential provided");
	}

	@Override
	public Saml2PostAuthenticationRequest createPostAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		String xml = context.getRelyingPartyRegistration().getAssertingPartyDetails().getWantAuthnRequestsSigned()
				? serialize(sign(authnRequest, context.getRelyingPartyRegistration())) : serialize(authnRequest);

		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))).build();
	}

	@Override
	public Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(
			Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		String xml = serialize(authnRequest);
		Builder result = Saml2RedirectAuthenticationRequest.withAuthenticationRequestContext(context);
		String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
		result.samlRequest(deflatedAndEncoded).relayState(context.getRelayState());
		if (context.getRelyingPartyRegistration().getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
			Map<String, String> parameters = new LinkedHashMap<>();
			parameters.put("SAMLRequest", deflatedAndEncoded);
			if (StringUtils.hasText(context.getRelayState())) {
				parameters.put("RelayState", context.getRelayState());
			}
			sign(parameters, context.getRelyingPartyRegistration());
			return result.sigAlg(parameters.get("SigAlg")).signature(parameters.get("Signature")).build();
		}
		return result.build();
	}

	private AuthnRequest createAuthnRequest(Saml2AuthenticationRequestContext context) {
		return createAuthnRequest(context.getIssuer(), context.getDestination(),
				context.getAssertionConsumerServiceUrl(), this.protocolBindingResolver.convert(context));
	}

	private AuthnRequest createAuthnRequest(String issuer, String destination, String assertionConsumerServiceUrl,
			String protocolBinding) {
		AuthnRequest auth = this.authnRequestBuilder.buildObject();
		auth.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		auth.setIssueInstant(new DateTime(this.clock.millis()));
		auth.setForceAuthn(Boolean.FALSE);
		auth.setIsPassive(Boolean.FALSE);
		auth.setProtocolBinding(protocolBinding);
		Issuer iss = this.issuerBuilder.buildObject();
		iss.setValue(issuer);
		auth.setIssuer(iss);
		auth.setDestination(destination);
		auth.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		return auth;
	}

	/**
	 * Set the {@link AuthnRequest} post-processor resolver
	 * @param authenticationRequestContextConverter
	 * @since 5.4
	 */
	public void setAuthenticationRequestContextConverter(
			Converter<Saml2AuthenticationRequestContext, AuthnRequest> authenticationRequestContextConverter) {
		Assert.notNull(authenticationRequestContextConverter, "authenticationRequestContextConverter cannot be null");
		this.authenticationRequestContextConverter = authenticationRequestContextConverter;
	}

	/**
	 * ' Use this {@link Clock} with {@link Instant#now()} for generating timestamps
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * Sets the {@code protocolBinding} to use when generating authentication requests.
	 * Acceptable values are {@link SAMLConstants#SAML2_POST_BINDING_URI} and
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI} The IDP will be reading this value
	 * in the {@code AuthNRequest} to determine how to send the Response/Assertion to the
	 * ACS URL, assertion consumer service URL.
	 * @param protocolBinding either {@link SAMLConstants#SAML2_POST_BINDING_URI} or
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * @throws IllegalArgumentException if the protocolBinding is not valid
	 * @deprecated Use
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.Builder#assertionConsumerServiceBinding(Saml2MessageBinding)}
	 * instead
	 */
	@Deprecated
	public void setProtocolBinding(String protocolBinding) {
		boolean isAllowedBinding = SAMLConstants.SAML2_POST_BINDING_URI.equals(protocolBinding)
				|| SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(protocolBinding);
		if (!isAllowedBinding) {
			throw new IllegalArgumentException("Invalid protocol binding: " + protocolBinding);
		}
		this.protocolBindingResolver = (context) -> protocolBinding;
	}

	private AuthnRequest sign(AuthnRequest authnRequest, RelyingPartyRegistration relyingPartyRegistration) {
		SignatureSigningParameters parameters = resolveSigningParameters(relyingPartyRegistration);
		return sign(authnRequest, parameters);
	}

	private AuthnRequest sign(AuthnRequest authnRequest, SignatureSigningParameters parameters) {
		try {
			SignatureSupport.signObject(authnRequest, parameters);
			return authnRequest;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private void sign(Map<String, String> components, RelyingPartyRegistration relyingPartyRegistration) {
		SignatureSigningParameters parameters = resolveSigningParameters(relyingPartyRegistration);
		sign(components, parameters);
	}

	private void sign(Map<String, String> components, SignatureSigningParameters parameters) {
		Credential credential = parameters.getSigningCredential();
		String algorithmUri = parameters.getSignatureAlgorithm();
		components.put("SigAlg", algorithmUri);
		UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
		for (Map.Entry<String, String> component : components.entrySet()) {
			builder.queryParam(component.getKey(), UriUtils.encode(component.getValue(), StandardCharsets.ISO_8859_1));
		}
		String queryString = builder.build(true).toString().substring(1);
		try {
			byte[] rawSignature = XMLSigningUtil.signWithURI(credential, algorithmUri,
					queryString.getBytes(StandardCharsets.UTF_8));
			String b64Signature = Saml2Utils.samlEncode(rawSignature);
			components.put("Signature", b64Signature);
		}
		catch (SecurityException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private String serialize(AuthnRequest authnRequest) {
		try {
			Element element = this.marshaller.marshall(authnRequest);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private SignatureSigningParameters resolveSigningParameters(RelyingPartyRegistration relyingPartyRegistration) {
		List<Credential> credentials = resolveSigningCredentials(relyingPartyRegistration);
		List<String> algorithms = relyingPartyRegistration.getAssertingPartyDetails().getSigningAlgorithms();
		List<String> digests = Collections.singletonList(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		String canonicalization = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
		SignatureSigningParametersResolver resolver = new SAMLMetadataSignatureSigningParametersResolver();
		CriteriaSet criteria = new CriteriaSet();
		BasicSignatureSigningConfiguration signingConfiguration = new BasicSignatureSigningConfiguration();
		signingConfiguration.setSigningCredentials(credentials);
		signingConfiguration.setSignatureAlgorithms(algorithms);
		signingConfiguration.setSignatureReferenceDigestMethods(digests);
		signingConfiguration.setSignatureCanonicalizationAlgorithm(canonicalization);
		criteria.add(new SignatureSigningConfigurationCriterion(signingConfiguration));
		try {
			SignatureSigningParameters parameters = resolver.resolveSingle(criteria);
			Assert.notNull(parameters, "Failed to resolve any signing credential");
			return parameters;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private List<Credential> resolveSigningCredentials(RelyingPartyRegistration relyingPartyRegistration) {
		List<Credential> credentials = new ArrayList<>();
		for (Saml2X509Credential x509Credential : relyingPartyRegistration.getSigningX509Credentials()) {
			X509Certificate certificate = x509Credential.getCertificate();
			PrivateKey privateKey = x509Credential.getPrivateKey();
			BasicCredential credential = CredentialSupport.getSimpleCredential(certificate, privateKey);
			credential.setEntityId(relyingPartyRegistration.getEntityId());
			credential.setUsageType(UsageType.SIGNING);
			credentials.add(credential);
		}
		return credentials;
	}

}
