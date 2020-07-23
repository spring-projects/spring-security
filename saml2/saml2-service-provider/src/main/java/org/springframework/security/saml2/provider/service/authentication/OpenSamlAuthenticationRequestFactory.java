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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest.Builder;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlDeflate;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlEncode;

/**
 * @since 5.2
 */
public class OpenSamlAuthenticationRequestFactory implements Saml2AuthenticationRequestFactory {
	static {
		OpenSamlInitializationService.initialize();
	}

	private Clock clock = Clock.systemUTC();
	private final OpenSamlImplementation saml = OpenSamlImplementation.getInstance();

	private Converter<Saml2AuthenticationRequestContext, String> protocolBindingResolver =
			context -> {
				if (context == null) {
					return SAMLConstants.SAML2_POST_BINDING_URI;
				}
				return context.getRelyingPartyRegistration().getAssertionConsumerServiceBinding().getUrn();
			};

	private Function<Saml2AuthenticationRequestContext, Consumer<AuthnRequest>> authnRequestConsumerResolver
			= context -> authnRequest -> {};

	@Override
	@Deprecated
	public String createAuthenticationRequest(Saml2AuthenticationRequest request) {
		AuthnRequest authnRequest = createAuthnRequest(request.getIssuer(),
				request.getDestination(), request.getAssertionConsumerServiceUrl(),
				this.protocolBindingResolver.convert(null));
		for (org.springframework.security.saml2.credentials.Saml2X509Credential credential : request.getCredentials()) {
			if (credential.isSigningCredential()) {
				Credential cred = getSigningCredential(credential.getCertificate(), credential.getPrivateKey(), request.getIssuer());
				signAuthnRequest(authnRequest, cred);
				return this.saml.serialize(authnRequest);
			}
		}
		throw new IllegalArgumentException("No signing credential provided");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2PostAuthenticationRequest createPostAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = createAuthnRequest(context);
		String xml = context.getRelyingPartyRegistration().getAssertingPartyDetails().getWantAuthnRequestsSigned() ?
			signThenSerialize(authnRequest, context.getRelyingPartyRegistration()) :
			this.saml.serialize(authnRequest);

		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(samlEncode(xml.getBytes(UTF_8)))
				.build();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = createAuthnRequest(context);
		String xml = this.saml.serialize(authnRequest);
		Builder result = Saml2RedirectAuthenticationRequest.withAuthenticationRequestContext(context);
		String deflatedAndEncoded = samlEncode(samlDeflate(xml));
		result.samlRequest(deflatedAndEncoded)
				.relayState(context.getRelayState());

		if (context.getRelyingPartyRegistration().getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
			Collection<Saml2X509Credential> signingCredentials = context.getRelyingPartyRegistration().getSigningX509Credentials();
			Map<String, String> signedParams = this.saml.signQueryParameters(
					signingCredentials,
					deflatedAndEncoded,
					context.getRelayState()
			);
			result.samlRequest(signedParams.get("SAMLRequest"))
					.relayState(signedParams.get("RelayState"))
					.sigAlg(signedParams.get("SigAlg"))
					.signature(signedParams.get("Signature"));
		}

		return result.build();
	}

	private AuthnRequest createAuthnRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = createAuthnRequest(context.getIssuer(),
				context.getDestination(), context.getAssertionConsumerServiceUrl(),
				this.protocolBindingResolver.convert(context));
		this.authnRequestConsumerResolver.apply(context).accept(authnRequest);
		return authnRequest;
	}

	private AuthnRequest createAuthnRequest
			(String issuer, String destination, String assertionConsumerServiceUrl, String protocolBinding) {
		AuthnRequest auth = this.saml.buildSamlObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
		auth.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		auth.setIssueInstant(new DateTime(this.clock.millis()));
		auth.setForceAuthn(Boolean.FALSE);
		auth.setIsPassive(Boolean.FALSE);
		auth.setProtocolBinding(protocolBinding);
		Issuer iss = this.saml.buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
		iss.setValue(issuer);
		auth.setIssuer(iss);
		auth.setDestination(destination);
		auth.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		return auth;
	}

	/**
	 * Set the {@link AuthnRequest} post-processor resolver
	 *
	 * @param authnRequestConsumerResolver
	 * @since 5.4
	 */
	public void setAuthnRequestConsumerResolver(
			Function<Saml2AuthenticationRequestContext, Consumer<AuthnRequest>> authnRequestConsumerResolver) {
		Assert.notNull(authnRequestConsumerResolver, "authnRequestConsumerResolver cannot be null");
		this.authnRequestConsumerResolver = authnRequestConsumerResolver;
	}

	/**
	 * '
	 * Use this {@link Clock} with {@link Instant#now()} for generating
	 * timestamps
	 *
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * Sets the {@code protocolBinding} to use when generating authentication requests.
	 * Acceptable values are {@link SAMLConstants#SAML2_POST_BINDING_URI} and
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * The IDP will be reading this value in the {@code AuthNRequest} to determine how to
	 * send the Response/Assertion to the ACS URL, assertion consumer service URL.
	 *
	 * @param protocolBinding either {@link SAMLConstants#SAML2_POST_BINDING_URI} or
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * @throws IllegalArgumentException if the protocolBinding is not valid
	 * @deprecated Use {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.Builder#assertionConsumerServiceBinding}
	 * instead
	 */
	@Deprecated
	public void setProtocolBinding(String protocolBinding) {
		boolean isAllowedBinding = SAMLConstants.SAML2_POST_BINDING_URI.equals(protocolBinding) ||
				SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(protocolBinding);
		if (!isAllowedBinding) {
			throw new IllegalArgumentException("Invalid protocol binding: " + protocolBinding);
		}
		this.protocolBindingResolver = context -> protocolBinding;
	}

	private String signThenSerialize(AuthnRequest authnRequest, RelyingPartyRegistration relyingPartyRegistration) {
		for (Saml2X509Credential credential : relyingPartyRegistration.getSigningX509Credentials()) {
			Credential cred = getSigningCredential(
					credential.getCertificate(), credential.getPrivateKey(), relyingPartyRegistration.getEntityId());
			signAuthnRequest(authnRequest, cred);
			return this.saml.serialize(authnRequest);
		}
		throw new IllegalArgumentException("No signing credential provided");
	}

	private void signAuthnRequest(AuthnRequest authnRequest, Credential credential) {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		try {
			SignatureSupport.signObject(authnRequest, parameters);
		} catch (MarshallingException | SignatureException | SecurityException e) {
			throw new Saml2Exception(e);
		}
	}

	private Credential getSigningCredential(X509Certificate certificate, PrivateKey privateKey, String entityId) {
		BasicCredential cred = CredentialSupport.getSimpleCredential(certificate, privateKey);
		cred.setEntityId(entityId);
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}
}
