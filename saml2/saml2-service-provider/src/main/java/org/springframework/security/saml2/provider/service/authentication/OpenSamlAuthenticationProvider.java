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

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.criteria.role.impl.EvaluableProtocolRoleDescriptorCriterion;
import org.opensaml.saml.saml2.assertion.ConditionValidator;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.criteria.impl.EvaluableEntityIDCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableUsageCredentialCriterion;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static java.util.Arrays.asList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters.CLOCK_SKEW;
import static org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters.COND_VALID_AUDIENCES;
import static org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS;
import static org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters.SIGNATURE_REQUIRED;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.DECRYPTION_ERROR;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INVALID_ASSERTION;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INVALID_DESTINATION;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INVALID_ISSUER;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INVALID_SIGNATURE;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.MALFORMED_RESPONSE_DATA;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.SUBJECT_NOT_FOUND;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.UNKNOWN_RESPONSE_CLASS;
import static org.springframework.util.Assert.notNull;

/**
 * Implementation of {@link AuthenticationProvider} for SAML authentications when receiving a
 * {@code Response} object containing an {@code Assertion}. This implementation uses
 * the {@code OpenSAML 3} library.
 *
 * <p>
 *  The {@link OpenSamlAuthenticationProvider} supports {@link Saml2AuthenticationToken} objects
 *  that contain a SAML response in its decoded XML format {@link Saml2AuthenticationToken#getSaml2Response()}
 *  along with the information about the asserting party, the identity provider (IDP), as well as
 *  the relying party, the service provider (SP, this application).
 * </p>
 * <p>
 *   The {@link Saml2AuthenticationToken} will be processed into a SAML Response object.
 *   The SAML response object can be signed. If the Response is signed, a signature will not be required on the assertion.
 * </p>
 * <p>
 *   While a response object can contain a list of assertion, this provider will only leverage
 *   the first valid assertion for the purpose of authentication. Assertions that do not pass validation
 *   will be ignored. If no valid assertions are found a {@link Saml2AuthenticationException} is thrown.
 * </p>
 * <p>
 *   This provider supports two types of encrypted SAML elements
 *   <ul>
 *     <li><a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=17">EncryptedAssertion</a></li>
 *     <li><a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=14">EncryptedID</a></li>
 *   </ul>
 *   If the assertion is encrypted, then signature validation on the assertion is no longer required.
 * </p>
 * <p>
 *   This provider does not perform an X509 certificate validation on the configured asserting party, IDP, verification
 *   certificates.
 * </p>
 * @since 5.2
 * @see <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=38">SAML 2 StatusResponse</a>
 * @see <a href="https://wiki.shibboleth.net/confluence/display/OS30/Home">OpenSAML 3</a>
 */
public final class OpenSamlAuthenticationProvider implements AuthenticationProvider {

	private static Log logger = LogFactory.getLog(OpenSamlAuthenticationProvider.class);

	private final OpenSamlImplementation saml = OpenSamlImplementation.getInstance();

	private Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor =
			(a -> singletonList(new SimpleGrantedAuthority("ROLE_USER")));
	private GrantedAuthoritiesMapper authoritiesMapper = (a -> a);
	private Duration responseTimeValidationSkew = Duration.ofMinutes(5);

	private Function<Saml2AuthenticationToken, Converter<Response, Map<String, Saml2AuthenticationException>>> responseValidator
			= validator(Arrays.asList(new ResponseSignatureValidator(), new ResponseValidator()));
	private Function<Saml2AuthenticationToken, Converter<EncryptedAssertion, Assertion>> assertionDecrypter
			= new AssertionDecrypter();
	private Function<Saml2AuthenticationToken, Converter<Assertion, Map<String, Saml2AuthenticationException>>> assertionValidator
			= validator(Arrays.asList(new AssertionSignatureValidator(), new AssertionValidator.Builder().build()));
	private Function<Saml2AuthenticationToken, Converter<EncryptedID, NameID>> principalDecrypter
			= new PrincipalDecrypter();
	private Function<Saml2AuthenticationToken, Converter<Response, AbstractAuthenticationToken>> authenticationConverter =
			token -> response -> {
				Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
				String username = assertion.getSubject().getNameID().getValue();
				Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
				return new Saml2Authentication(
						new SimpleSaml2AuthenticatedPrincipal(username, attributes), token.getSaml2Response(),
						this.authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion)));
			};

	/**
	 * Sets the {@link Converter} used for extracting assertion attributes that
	 * can be mapped to authorities.
	 * @param authoritiesExtractor the {@code Converter} used for mapping the
	 *                             assertion attributes to authorities
	 */
	public void setAuthoritiesExtractor(Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor) {
		Assert.notNull(authoritiesExtractor, "authoritiesExtractor cannot be null");
		this.authoritiesExtractor = authoritiesExtractor;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for mapping assertion attributes
	 * to a new set of authorities which will be associated to the {@link Saml2Authentication}.
	 * Note: This implementation is only retrieving
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
	 */
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * Sets the duration for how much time skew an assertion may tolerate during
	 * timestamp, NotOnOrBefore and NotOnOrAfter, validation.
	 * @param responseTimeValidationSkew duration for skew tolerance
	 */
	public void setResponseTimeValidationSkew(Duration responseTimeValidationSkew) {
		this.responseTimeValidationSkew = responseTimeValidationSkew;
		this.assertionValidator = validator(Arrays.asList(
				new AssertionSignatureValidator(),
				new AssertionValidator.Builder()
					.validationContext(params -> params
							.put(CLOCK_SKEW, responseTimeValidationSkew.toMillis()))
					.build()));
	}

	/**
	 * @param authentication the authentication request object, must be of type
	 *                       {@link Saml2AuthenticationToken}
	 *
	 * @return {@link Saml2Authentication} if the assertion is valid
	 * @throws AuthenticationException if a validation exception occurs
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			Saml2AuthenticationToken token = (Saml2AuthenticationToken) authentication;
			String serializedResponse = token.getSaml2Response();
			Response response = parse(serializedResponse);
			process(token, response);
			return this.authenticationConverter.apply(token).convert(response);
		} catch (Saml2AuthenticationException e) {
			throw e;
		} catch (Exception e) {
			throw authException(INTERNAL_VALIDATION_ERROR, e.getMessage(), e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication != null && Saml2AuthenticationToken.class.isAssignableFrom(authentication);
	}

	private Collection<? extends GrantedAuthority> getAssertionAuthorities(Assertion assertion) {
		return this.authoritiesExtractor.convert(assertion);
	}

	private Response parse(String response) throws Saml2Exception, Saml2AuthenticationException {
		try {
			Object result = this.saml.resolve(response);
			if (result instanceof Response) {
				return (Response) result;
			}
			else {
				throw authException(UNKNOWN_RESPONSE_CLASS, "Invalid response class:" + result.getClass().getName());
			}
		} catch (Saml2Exception x) {
			throw authException(MALFORMED_RESPONSE_DATA, x.getMessage(), x);
		}

	}

	private void process(Saml2AuthenticationToken token, Response response) {
		String issuer = response.getIssuer().getValue();
		if (logger.isDebugEnabled()) {
			logger.debug("Processing SAML response from " + issuer);
		}

		boolean responseSigned = response.isSigned();
		Map<String, Saml2AuthenticationException> validationExceptions = validateResponse(token, response);

		List<Assertion> assertions = decryptAssertions(token, response);
		if (!isSigned(responseSigned, assertions)) {
			throw authException(INVALID_SIGNATURE, "Either the response or one of the assertions is unsigned. " +
					"Please either sign the response or all of the assertions.");
		}
		validationExceptions.putAll(validateAssertions(token, assertions));

		Assertion firstAssertion = CollectionUtils.firstElement(response.getAssertions());
		NameID nameId = decryptPrincipal(token, firstAssertion);
		if (nameId == null || nameId.getValue() == null) {
			validationExceptions.put(SUBJECT_NOT_FOUND, authException(SUBJECT_NOT_FOUND,
					"Assertion [" + firstAssertion.getID() + "] is missing a subject"));
		}

		if (validationExceptions.isEmpty()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Successfully processed SAML Response [" + response.getID() + "]");
			}
		} else {
			if (logger.isTraceEnabled()) {
				logger.debug("Found " + validationExceptions.size() + " validation errors in SAML response [" + response.getID() + "]: " +
						validationExceptions.values());
			} else if (logger.isDebugEnabled()) {
				logger.debug("Found " + validationExceptions.size() + " validation errors in SAML response [" + response.getID() + "]");
			}
		}

		if (!validationExceptions.isEmpty()) {
			throw validationExceptions.values().iterator().next();
		}
	}

	private Map<String, Saml2AuthenticationException> validateResponse
			(Saml2AuthenticationToken token, Response response) {

		Map<String, Saml2AuthenticationException> validationExceptions = new HashMap<>();
		validationExceptions.putAll(this.responseValidator.apply(token).convert(response));
		return validationExceptions;
	}

	private List<Assertion> decryptAssertions
			(Saml2AuthenticationToken token, Response response) {
		List<Assertion> assertions = new ArrayList<>();
		for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
			Assertion assertion = this.assertionDecrypter.apply(token).convert(encryptedAssertion);
			assertions.add(assertion);
		}
		response.getAssertions().addAll(assertions);
		return response.getAssertions();
	}

	private Map<String, Saml2AuthenticationException> validateAssertions
			(Saml2AuthenticationToken token, List<Assertion> assertions) {
		if (assertions.isEmpty()) {
			throw authException(MALFORMED_RESPONSE_DATA, "No assertions found in response.");
		}

		Map<String, Saml2AuthenticationException> validationExceptions = new LinkedHashMap<>();
		if (logger.isDebugEnabled()) {
			logger.debug("Validating " + assertions.size() + " assertions");
		}
		for (Assertion assertion : assertions) {
			if (logger.isTraceEnabled()) {
				logger.trace("Validating assertion " + assertion.getID());
			}
			validationExceptions.putAll(this.assertionValidator.apply(token).convert(assertion));
		}

		return validationExceptions;
	}

	private boolean isSigned(boolean responseSigned, List<Assertion> assertions) {
		if (responseSigned) {
			return true;
		}

		for (Assertion assertion : assertions) {
			if (!assertion.isSigned()) {
				return false;
			}
		}

		return true;
	}

	private NameID decryptPrincipal(Saml2AuthenticationToken token, Assertion assertion) {
		if (assertion.getSubject() == null) {
			return null;
		}
		if (assertion.getSubject().getEncryptedID() == null) {
			return assertion.getSubject().getNameID();
		}
		NameID nameId = this.principalDecrypter.apply(token).convert(assertion.getSubject().getEncryptedID());
		assertion.getSubject().setNameID(nameId);
		return nameId;
	}

	private Map<String, List<Object>> getAssertionAttributes(Assertion assertion) {
		Map<String, List<Object>> attributeMap = new LinkedHashMap<>();
		for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
			for (Attribute attribute : attributeStatement.getAttributes()) {

				List<Object> attributeValues = new ArrayList<>();
				for (XMLObject xmlObject : attribute.getAttributeValues()) {
					Object attributeValue = getXmlObjectValue(xmlObject);
					if (attributeValue != null) {
						attributeValues.add(attributeValue);
					}
				}
				attributeMap.put(attribute.getName(), attributeValues);

			}
		}
		return attributeMap;
	}

	private Object getXmlObjectValue(XMLObject xmlObject) {
		if (xmlObject instanceof XSAny) {
			return getXSAnyObjectValue((XSAny) xmlObject);
		}
		if (xmlObject instanceof XSString) {
			return ((XSString) xmlObject).getValue();
		}
		if (xmlObject instanceof XSInteger) {
			return ((XSInteger) xmlObject).getValue();
		}
		if (xmlObject instanceof XSURI) {
			return ((XSURI) xmlObject).getValue();
		}
		if (xmlObject instanceof XSBoolean) {
			XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).getValue();
			return xsBooleanValue != null ? xsBooleanValue.getValue() : null;
		}
		if (xmlObject instanceof XSDateTime) {
			DateTime dateTime = ((XSDateTime) xmlObject).getValue();
			return dateTime != null ? Instant.ofEpochMilli(dateTime.getMillis()) : null;
		}
		return null;
	}

	private Object getXSAnyObjectValue(XSAny xsAny) {
		Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xsAny);
		if (marshaller != null) {
			return this.saml.serialize(xsAny);
		}
		return xsAny.getTextContent();
	}

	private static <T extends XMLObject> Function<Saml2AuthenticationToken, Converter<T, Map<String, Saml2AuthenticationException>>>
			validator(Collection<Function<Saml2AuthenticationToken, Converter<T, Map<String, Saml2AuthenticationException>>>> validators) {
		return token -> response -> {
			Map<String, Saml2AuthenticationException> errors = new LinkedHashMap<>();
			for (Function<Saml2AuthenticationToken, Converter<T, Map<String, Saml2AuthenticationException>>> validator : validators) {
				errors.putAll(validator.apply(token).convert(response));
			}
			return errors;
		};
	}

	private static class ResponseSignatureValidator implements
			Function<Saml2AuthenticationToken, Converter<Response, Map<String, Saml2AuthenticationException>>> {

		private final SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();

		@Override
		public Converter<Response, Map<String, Saml2AuthenticationException>> apply(Saml2AuthenticationToken token) {
			return response -> {
				Map<String, Saml2AuthenticationException> validationExceptions = new LinkedHashMap<>();
				String issuer = response.getIssuer().getValue();
				if (response.isSigned()) {
					try {
						this.profileValidator.validate(response.getSignature());
					} catch (Exception e) {
						validationExceptions.put(INVALID_SIGNATURE, authException(INVALID_SIGNATURE,
								"Invalid signature for SAML Response [" + response.getID() + "]: ", e));
					}

					try {
						CriteriaSet criteriaSet = new CriteriaSet();
						criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
						criteriaSet.add(new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
						criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
						if (!buildSignatureTrustEngine(token).validate(response.getSignature(), criteriaSet)) {
							validationExceptions.put(INVALID_SIGNATURE, authException(INVALID_SIGNATURE,
									"Invalid signature for SAML Response [" + response.getID() + "]"));
						}
					} catch (Exception e) {
						validationExceptions.put(INVALID_SIGNATURE, authException(INVALID_SIGNATURE,
								"Invalid signature for SAML Response [" + response.getID() + "]: ", e));
					}
				}

				return validationExceptions;
			};
		}

		private SignatureTrustEngine buildSignatureTrustEngine(Saml2AuthenticationToken token) {
			Set<Credential> credentials = new HashSet<>();
			for (Saml2X509Credential key : token.getX509Credentials()) {
				if (!key.isSignatureVerficationCredential()) {
					continue;
				}
				BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
				cred.setUsageType(UsageType.SIGNING);
				cred.setEntityId(token.getIdpEntityId());
				credentials.add(cred);
			}
			CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
			return new ExplicitKeySignatureTrustEngine(
					credentialsResolver,
					DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
			);
		}
	}

	private static class ResponseValidator
			implements Function<Saml2AuthenticationToken, Converter<Response, Map<String, Saml2AuthenticationException>>> {

		@Override
		public Converter<Response, Map<String, Saml2AuthenticationException>> apply(Saml2AuthenticationToken token) {
			return response -> {
				Map<String, Saml2AuthenticationException> validationExceptions = new LinkedHashMap<>();

				String destination = response.getDestination();
				if (StringUtils.hasText(destination) && !destination.equals(token.getRecipientUri())) {
					String message = "Invalid destination [" + destination + "] for SAML response [" + response.getID() + "]";
					validationExceptions.put(INVALID_DESTINATION, authException(INVALID_DESTINATION, message));
				}

				String issuer = response.getIssuer().getValue();
				String assertingPartyEntityId = token.getIdpEntityId();
				if (!StringUtils.hasText(issuer) || !issuer.equals(assertingPartyEntityId)) {
					String message = String.format("Invalid issuer [%s] for SAML response [%s]", issuer, response.getID());
					validationExceptions.put(INVALID_ISSUER, authException(INVALID_ISSUER, message));
				}

				return validationExceptions;
			};
		}
	}

	private static class AssertionDecrypter
			implements Function<Saml2AuthenticationToken, Converter<EncryptedAssertion, Assertion>> {
		private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
				asList(
						new InlineEncryptedKeyResolver(),
						new EncryptedElementTypeEncryptedKeyResolver(),
						new SimpleRetrievalMethodEncryptedKeyResolver()
				)
		);

		@Override
		public Converter<EncryptedAssertion, Assertion> apply(Saml2AuthenticationToken token) {
			return encrypted -> {
				Saml2AuthenticationException last =
						authException(DECRYPTION_ERROR, "No valid decryption credentials found.");
				List<Saml2X509Credential> decryptionCredentials = token.getX509Credentials();
				for (Saml2X509Credential key : decryptionCredentials) {
					if (!key.isDecryptionCredential()) {
						continue;
					}
					Decrypter decrypter = getDecrypter(key);
					try {
						return decrypter.decrypt(encrypted);
					} catch (DecryptionException e) {
						last = authException(DECRYPTION_ERROR, e.getMessage(), e);
					}
				}
				throw last;
			};
		}

		private Decrypter getDecrypter(Saml2X509Credential key) {
			Credential credential = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
			KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
			Decrypter decrypter = new Decrypter(null, resolver, this.encryptedKeyResolver);
			decrypter.setRootInNewDocument(true);
			return decrypter;
		}
	}

	private static class AssertionSignatureValidator
			implements Function<Saml2AuthenticationToken, Converter<Assertion, Map<String, Saml2AuthenticationException>>> {

		private final SignaturePrevalidator signaturePrevalidator = new SAMLSignatureProfileValidator();

		@Override
		public Converter<Assertion, Map<String, Saml2AuthenticationException>> apply(Saml2AuthenticationToken token) {
			return assertion -> {
				Map<String, Saml2AuthenticationException> validationExceptions = new LinkedHashMap<>();
				try {
					ValidationContext context = buildValidationContext();
					ValidationResult result = buildSamlAssertionValidator(token).validate(assertion, context);
					if (result != ValidationResult.VALID) {
						String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
								assertion.getID(), ((Response) assertion.getParent()).getID(),
								context.getValidationFailureMessage());
						validationExceptions.put(INVALID_ASSERTION, authException(INVALID_ASSERTION, message));
					}
				} catch (Exception e) {
					String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
							assertion.getID(), ((Response) assertion.getParent()).getID(),
							e.getMessage());
					validationExceptions.put(INVALID_ASSERTION, authException(INVALID_ASSERTION, message, e));
				}
				return validationExceptions;
			};
		}

		private ValidationContext buildValidationContext() {
			Map<String, Object> validationParams = new HashMap<>();
			validationParams.put(SIGNATURE_REQUIRED, Boolean.FALSE); // this requirement is checked earlier
			return new ValidationContext(validationParams);
		}

		private SAML20AssertionValidator buildSamlAssertionValidator(Saml2AuthenticationToken token) {
			SignatureTrustEngine signatureTrustEngine = buildSignatureTrustEngine(token);
			return new SAML20AssertionValidator(
					Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), signatureTrustEngine, signaturePrevalidator) {
				@Nonnull
				@Override
				protected ValidationResult validateConditions(@Nonnull Assertion assertion, @Nonnull ValidationContext context) {
					return ValidationResult.VALID;
				}

				@Nonnull
				@Override
				protected ValidationResult validateSubjectConfirmation(@Nonnull Assertion assertion, @Nonnull ValidationContext context) {
					return ValidationResult.VALID;
				}

				@Nonnull
				@Override
				protected ValidationResult validateStatements(@Nonnull Assertion assertion, @Nonnull ValidationContext context) {
					return ValidationResult.VALID;
				}
			};
		}

		private SignatureTrustEngine buildSignatureTrustEngine(Saml2AuthenticationToken token) {
			Set<Credential> credentials = new HashSet<>();
			for (Saml2X509Credential key : token.getX509Credentials()) {
				if (!key.isSignatureVerficationCredential()) continue;
				BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
				cred.setUsageType(UsageType.SIGNING);
				cred.setEntityId(token.getIdpEntityId());
				credentials.add(cred);
			}
			CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
			return new ExplicitKeySignatureTrustEngine(
					credentialsResolver,
					DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
			);
		}
	}

	private static class AssertionValidator
			implements Function<Saml2AuthenticationToken, Converter<Assertion, Map<String, Saml2AuthenticationException>>> {

		private final Function<Saml2AuthenticationToken, ValidationContext> validationContextResolver;
		private final Function<Saml2AuthenticationToken, SAML20AssertionValidator> assertionValidatorResolver;

		AssertionValidator(Function<Saml2AuthenticationToken, SAML20AssertionValidator> assertionValidatorResolver,
			Function<Saml2AuthenticationToken, ValidationContext> validationContextResolver) {

			this.validationContextResolver = validationContextResolver;
			this.assertionValidatorResolver = assertionValidatorResolver;
		}

		@Override
		public Converter<Assertion, Map<String, Saml2AuthenticationException>> apply(Saml2AuthenticationToken token) {
			return assertion -> {
				Map<String, Saml2AuthenticationException> validationExceptions = new LinkedHashMap<>();
				try {
					ValidationContext context = this.validationContextResolver.apply(token);
					ValidationResult result = this.assertionValidatorResolver.apply(token).validate(assertion, context);
					if (result != ValidationResult.VALID) {
						String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
								assertion.getID(), ((Response) assertion.getParent()).getID(),
								context.getValidationFailureMessage());
						validationExceptions.put(INVALID_ASSERTION, authException(INVALID_ASSERTION, message));
					}
				} catch (Exception e) {
					String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
							assertion.getID(), ((Response) assertion.getParent()).getID(),
							e.getMessage());
					validationExceptions.put(INVALID_ASSERTION, authException(INVALID_ASSERTION, message, e));
				}
				return validationExceptions;
			};
		}

		private static class Builder {
			private final Collection<ConditionValidator> conditions = new ArrayList<>();
			private final Collection<SubjectConfirmationValidator> subjects = new ArrayList<>();
			private final Collection<StatementValidator> statements = new ArrayList<>();
			private final Map<String, Object> validationContextParameters = new HashMap<>();

			Builder() {
				this.conditions.add(new AudienceRestrictionConditionValidator());
				this.subjects.add(new BearerSubjectConfirmationValidator() {
					@Nonnull
					@Override
					protected ValidationResult validateAddress(@Nonnull SubjectConfirmation confirmation,
							@Nonnull Assertion assertion, @Nonnull ValidationContext context) {
						// skipping address validation - gh-7514
						return ValidationResult.VALID;
					}
				});
			}

			public AssertionValidator.Builder validationContext(
					Consumer<Map<String, Object>> validationContextParameters) {
				validationContextParameters.accept(this.validationContextParameters);
				return this;
			}

			public AssertionValidator build() {
				return new AssertionValidator(
						token -> new SAML20AssertionValidator(this.conditions, this.subjects, this.statements, null, null) {
							@Nonnull
							@Override
							protected ValidationResult validateSignature(@Nonnull Assertion token, @Nonnull ValidationContext context) {
								return ValidationResult.VALID;
							}
						},
						token -> {
							Map<String, Object> params = new HashMap<>();
							params.put(CLOCK_SKEW, Duration.ofMinutes(5).toMillis());
							params.put(COND_VALID_AUDIENCES, singleton(token.getIdpEntityId()));
							params.put(SC_VALID_RECIPIENTS, singleton(token.getRecipientUri()));
							params.putAll(this.validationContextParameters);
							return new ValidationContext(params);
						});
			}
		}
	}

	private static class PrincipalDecrypter implements Function<Saml2AuthenticationToken, Converter<EncryptedID, NameID>> {
		private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
				asList(
						new InlineEncryptedKeyResolver(),
						new EncryptedElementTypeEncryptedKeyResolver(),
						new SimpleRetrievalMethodEncryptedKeyResolver()
				)
		);

		@Override
		public Converter<EncryptedID, NameID> apply(Saml2AuthenticationToken token) {
			return encrypted -> {
				Saml2AuthenticationException last =
						authException(DECRYPTION_ERROR, "No valid decryption credentials found.");
				List<Saml2X509Credential> decryptionCredentials = token.getX509Credentials();
				for (Saml2X509Credential key : decryptionCredentials) {
					if (!key.isDecryptionCredential()) continue;
					Decrypter decrypter = getDecrypter(key);
					try {
						return (NameID) decrypter.decrypt(encrypted);
					} catch (DecryptionException e) {
						last = authException(DECRYPTION_ERROR, e.getMessage(), e);
					}
				}
				throw last;
			};
		}

		private Decrypter getDecrypter(Saml2X509Credential key) {
			Credential credential = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
			KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
			Decrypter decrypter = new Decrypter(null, resolver, this.encryptedKeyResolver);
			decrypter.setRootInNewDocument(true);
			return decrypter;
		}
	}

	private static Saml2Error validationError(String code, String description) {
		return new Saml2Error(code, description);
	}

	private static Saml2AuthenticationException authException(String code, String description)
			throws Saml2AuthenticationException {

		return new Saml2AuthenticationException(validationError(code, description));
	}

	private static Saml2AuthenticationException authException(String code, String description, Exception cause)
			throws Saml2AuthenticationException {

		return new Saml2AuthenticationException(validationError(code, description), cause);
	}
}
