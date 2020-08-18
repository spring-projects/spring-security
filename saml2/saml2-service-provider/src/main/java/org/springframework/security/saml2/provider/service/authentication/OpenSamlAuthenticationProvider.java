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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
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
import org.opensaml.saml.saml2.assertion.impl.DelegationRestrictionConditionValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
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
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
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
import static org.springframework.security.saml2.core.Saml2ErrorCodes.DECRYPTION_ERROR;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_ASSERTION;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_DESTINATION;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_ISSUER;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_SIGNATURE;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.MALFORMED_RESPONSE_DATA;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.SUBJECT_NOT_FOUND;
import static org.springframework.security.saml2.core.Saml2ResponseValidatorResult.failure;
import static org.springframework.security.saml2.core.Saml2ResponseValidatorResult.success;
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

	static {
		OpenSamlInitializationService.initialize();
	}

	private static Log logger = LogFactory.getLog(OpenSamlAuthenticationProvider.class);

	private final XMLObjectProviderRegistry registry;
	private final ResponseUnmarshaller responseUnmarshaller;
	private final ParserPool parserPool;

	private Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor =
			(a -> singletonList(new SimpleGrantedAuthority("ROLE_USER")));
	private GrantedAuthoritiesMapper authoritiesMapper = (a -> a);
	private Duration responseTimeValidationSkew = Duration.ofMinutes(5);

	private Function<Saml2AuthenticationToken, Converter<Response, AbstractAuthenticationToken>> authenticationConverter =
			token -> response -> {
				Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
				String username = assertion.getSubject().getNameID().getValue();
				Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
				return new Saml2Authentication(
						new DefaultSaml2AuthenticatedPrincipal(username, attributes), token.getSaml2Response(),
						this.authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion)));
			};

	private Converter<AssertionToken, Saml2ResponseValidatorResult> assertionValidator = assertionToken -> {
		ValidationContext context = createValidationContext(assertionToken);
		return createDefaultAssertionValidator(context).convert(assertionToken);
	};

	private Converter<Saml2AuthenticationToken, SignatureTrustEngine> signatureTrustEngineConverter =
			new SignatureTrustEngineConverter();
	private Converter<Saml2AuthenticationToken, Decrypter> decrypterConverter = new DecrypterConverter();


	/**
	 * Creates an {@link OpenSamlAuthenticationProvider}
	 */
	public OpenSamlAuthenticationProvider() {
		this.registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.responseUnmarshaller = (ResponseUnmarshaller) this.registry.getUnmarshallerFactory()
				.getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
		this.parserPool = this.registry.getParserPool();
	}

	/**
	 * Set the {@link Converter} to use for validating each {@link Assertion} in the SAML 2.0 Response.
	 *
	 * You can still invoke the default validator by delgating to
	 * {@link #createDefaultAssertionValidator(ValidationContext)}, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *  provider.setAssertionValidator(assertionToken -> {
	 *		ValidationContext context = // ... build using authentication token
	 *		Saml2ResponseValidatorResult result = createDefaultAssertionValidator(context)
	 *			.convert(assertionToken)
	 *		return result.concat(myCustomValiator.convert(assertionToken));
	 *  });
	 * </pre>
	 *
	 * Consider taking a look at {@link #createValidationContext(AssertionToken)} to see how it
	 * constructs a {@link ValidationContext}.
	 *
	 * You can also use this method to configure the provider to use a different
	 * {@link ValidationContext} from the default, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	ValidationContext context = // ...
	 *	provider.setAssertionValidator(createDefaultAssertionValidator(context));
	 * </pre>
	 *
	 * It is not necessary to delegate to the default validator. You can safely replace it
	 * entirely with your own. Note that signature verification is performed as a separate
	 * step from this validator.
	 *
	 * @param assertionValidator
	 * @since 5.4
	 */
	public void setAssertionValidator(Converter<AssertionToken, Saml2ResponseValidatorResult> assertionValidator) {
		Assert.notNull(assertionValidator, "assertionValidator cannot be null");
		this.assertionValidator = assertionValidator;
	}

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
			Document document = this.parserPool.parse(new ByteArrayInputStream(
					response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (Response) this.responseUnmarshaller.unmarshall(element);
		}
		catch (Exception e) {
			throw authException(MALFORMED_RESPONSE_DATA, e.getMessage(), e);
		}
	}

	private void process(Saml2AuthenticationToken token, Response response) {
		String issuer = response.getIssuer().getValue();
		if (logger.isDebugEnabled()) {
			logger.debug("Processing SAML response from " + issuer);
		}

		boolean responseSigned = response.isSigned();
		Saml2ResponseValidatorResult result = validateResponse(token, response);

		Decrypter decrypter = this.decrypterConverter.convert(token);
		List<Assertion> assertions = decryptAssertions(decrypter, response);
		if (!isSigned(responseSigned, assertions)) {
			throw authException(INVALID_SIGNATURE, "Either the response or one of the assertions is unsigned. " +
					"Please either sign the response or all of the assertions.");
		}
		result = result.concat(validateAssertions(token, response));

		Assertion firstAssertion = CollectionUtils.firstElement(response.getAssertions());
		NameID nameId = decryptPrincipal(decrypter, firstAssertion);
		if (nameId == null || nameId.getValue() == null) {
			Saml2Error error = new Saml2Error(SUBJECT_NOT_FOUND,
					"Assertion [" + firstAssertion.getID() + "] is missing a subject");
			result = result.concat(error);
		}

		if (result.hasErrors()) {
			Collection<Saml2Error> errors = result.getErrors();
			if (logger.isTraceEnabled()) {
				logger.debug("Found " + errors.size() + " validation errors in SAML response [" + response.getID() + "]: " +
						errors);
			} else if (logger.isDebugEnabled()) {
				logger.debug("Found " + errors.size() + " validation errors in SAML response [" + response.getID() + "]");
			}
			Saml2Error first = errors.iterator().next();
			throw authException(first.getErrorCode(), first.getDescription());
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("Successfully processed SAML Response [" + response.getID() + "]");
			}
		}
	}

	private Saml2ResponseValidatorResult validateResponse
			(Saml2AuthenticationToken token, Response response) {

		Collection<Saml2Error> errors = new ArrayList<>();
		String issuer = response.getIssuer().getValue();

		if (response.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(response.getSignature());
			} catch (Exception e) {
				errors.add(new Saml2Error(INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + response.getID() + "]: "));
			}

			try {
				CriteriaSet criteriaSet = new CriteriaSet();
				criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
				criteriaSet.add(new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
				criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
				if (!this.signatureTrustEngineConverter.convert(token).validate(response.getSignature(), criteriaSet)) {
					errors.add(new Saml2Error(INVALID_SIGNATURE,
							"Invalid signature for SAML Response [" + response.getID() + "]"));
				}
			} catch (Exception e) {
				errors.add(new Saml2Error(INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + response.getID() + "]: "));
			}
		}

		String destination = response.getDestination();
		String location = token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
		if (StringUtils.hasText(destination) && !destination.equals(location)) {
			String message = "Invalid destination [" + destination + "] for SAML response [" + response.getID() + "]";
			errors.add(new Saml2Error(INVALID_DESTINATION, message));
		}

		String assertingPartyEntityId = token.getRelyingPartyRegistration().getAssertingPartyDetails().getEntityId();
		if (!StringUtils.hasText(issuer) || !issuer.equals(assertingPartyEntityId)) {
			String message = String.format("Invalid issuer [%s] for SAML response [%s]", issuer, response.getID());
			errors.add(new Saml2Error(INVALID_ISSUER, message));
		}

		return failure(errors);
	}

	private List<Assertion> decryptAssertions
			(Decrypter decrypter, Response response) {
		List<Assertion> assertions = new ArrayList<>();
		for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
			try {
				Assertion assertion = decrypter.decrypt(encryptedAssertion);
				assertions.add(assertion);
			} catch (DecryptionException e) {
				throw authException(DECRYPTION_ERROR, e.getMessage(), e);
			}
		}
		response.getAssertions().addAll(assertions);
		return response.getAssertions();
	}

	private Saml2ResponseValidatorResult validateAssertions
			(Saml2AuthenticationToken token, Response response) {
		List<Assertion> assertions = response.getAssertions();
		if (assertions.isEmpty()) {
			throw authException(MALFORMED_RESPONSE_DATA, "No assertions found in response.");
		}

		Saml2ResponseValidatorResult result = success();
		if (logger.isDebugEnabled()) {
			logger.debug("Validating " + assertions.size() + " assertions");
		}

		ValidationContext signatureContext = new ValidationContext
				(Collections.singletonMap(SIGNATURE_REQUIRED, false)); // check already performed
		SignatureTrustEngine engine = this.signatureTrustEngineConverter.convert(token);
		Converter<AssertionToken, Saml2ResponseValidatorResult> signatureValidator =
				createDefaultAssertionValidator(INVALID_SIGNATURE,
						SAML20AssertionValidators.createSignatureValidator(engine), signatureContext);
		for (Assertion assertion : assertions) {
			if (logger.isTraceEnabled()) {
				logger.trace("Validating assertion " + assertion.getID());
			}
			AssertionToken assertionToken = new AssertionToken(assertion, token);
			result = result
					.concat(signatureValidator.convert(assertionToken))
					.concat(this.assertionValidator.convert(assertionToken));
		}

		return result;
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

	private NameID decryptPrincipal(Decrypter decrypter, Assertion assertion) {
		if (assertion.getSubject() == null) {
			return null;
		}
		if (assertion.getSubject().getEncryptedID() == null) {
			return assertion.getSubject().getNameID();
		}
		try {
			NameID nameId = (NameID) decrypter.decrypt(assertion.getSubject().getEncryptedID());
			assertion.getSubject().setNameID(nameId);
			return nameId;
		} catch (DecryptionException e) {
			throw authException(DECRYPTION_ERROR, e.getMessage(), e);
		}
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
			return ((XSAny) xmlObject).getTextContent();
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

	private static class SignatureTrustEngineConverter implements Converter<Saml2AuthenticationToken, SignatureTrustEngine> {

		@Override
		public SignatureTrustEngine convert(Saml2AuthenticationToken token) {
			Set<Credential> credentials = new HashSet<>();
			Collection<Saml2X509Credential> keys = token.getRelyingPartyRegistration().getAssertingPartyDetails().getVerificationX509Credentials();
			for (Saml2X509Credential key : keys) {
				BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
				cred.setUsageType(UsageType.SIGNING);
				cred.setEntityId(token.getRelyingPartyRegistration().getAssertingPartyDetails().getEntityId());
				credentials.add(cred);
			}
			CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
			return new ExplicitKeySignatureTrustEngine(
					credentialsResolver,
					DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
			);
		}
	}

	public static Converter<AssertionToken, Saml2ResponseValidatorResult>
			createDefaultAssertionValidator(ValidationContext context) {

		return createDefaultAssertionValidator(INVALID_ASSERTION,
				SAML20AssertionValidators.createAttributeValidator(), context);
	}

	private static Converter<AssertionToken, Saml2ResponseValidatorResult>
			createDefaultAssertionValidator(String errorCode, SAML20AssertionValidator validator, ValidationContext context) {

		return assertionToken -> {
			Assertion assertion = assertionToken.assertion;
			try {
				ValidationResult result = validator.validate(assertion, context);
				if (result == ValidationResult.VALID) {
					return success();
				}
			} catch (Exception e) {
				String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
						assertion.getID(), ((Response) assertion.getParent()).getID(),
						e.getMessage());
				return failure(new Saml2Error(errorCode, message));
			}
			String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
					assertion.getID(), ((Response) assertion.getParent()).getID(),
					context.getValidationFailureMessage());
			return failure(new Saml2Error(errorCode, message));
		};
	}

	private ValidationContext createValidationContext(AssertionToken assertionToken) {
		String audience = assertionToken.token.getRelyingPartyRegistration().getEntityId();
		String recipient = assertionToken.token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
		Map<String, Object> params = new HashMap<>();
		params.put(CLOCK_SKEW, OpenSamlAuthenticationProvider.this.responseTimeValidationSkew.toMillis());
		params.put(COND_VALID_AUDIENCES, singleton(audience));
		params.put(SC_VALID_RECIPIENTS, singleton(recipient));
		return new ValidationContext(params);
	}

	private static class SAML20AssertionValidators {
		private static final Collection<ConditionValidator> conditions = new ArrayList<>();
		private static final Collection<SubjectConfirmationValidator> subjects = new ArrayList<>();
		private static final Collection<StatementValidator> statements = new ArrayList<>();
		private static final SignaturePrevalidator validator = new SAMLSignatureProfileValidator();

		static {
			conditions.add(new AudienceRestrictionConditionValidator());
			conditions.add(new DelegationRestrictionConditionValidator());
			conditions.add(new ConditionValidator() {
				@Nonnull
				@Override
				public QName getServicedCondition() {
					return OneTimeUse.DEFAULT_ELEMENT_NAME;
				}

				@Nonnull
				@Override
				public ValidationResult validate(Condition condition, Assertion assertion, ValidationContext context) {
					// applications should validate their own OneTimeUse conditions
					return ValidationResult.VALID;
				}
			});
			subjects.add(new BearerSubjectConfirmationValidator() {
				@Nonnull
				@Override
				protected ValidationResult validateAddress(@Nonnull SubjectConfirmation confirmation,
						@Nonnull Assertion assertion, @Nonnull ValidationContext context) {
					// applications should validate their own addresses - gh-7514
					return ValidationResult.VALID;
				}
			});
		}

		static SAML20AssertionValidator createAttributeValidator() {
			return new SAML20AssertionValidator(conditions, subjects, statements, null, null) {
				@Nonnull
				@Override
				protected ValidationResult validateSignature(Assertion token, ValidationContext context) {
					return ValidationResult.VALID;
				}
			};
		}

		static SAML20AssertionValidator createSignatureValidator(SignatureTrustEngine engine) {
			return new SAML20AssertionValidator(new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
					engine, validator) {
				@Nonnull
				@Override
				protected ValidationResult validateConditions(Assertion assertion, ValidationContext context) {
					return ValidationResult.VALID;
				}

				@Nonnull
				@Override
				protected ValidationResult validateSubjectConfirmation(Assertion assertion, ValidationContext context) {
					return ValidationResult.VALID;
				}

				@Nonnull
				@Override
				protected ValidationResult validateStatements(Assertion assertion, ValidationContext context) {
					return ValidationResult.VALID;
				}
			};
		}
	}

	private static class DecrypterConverter implements Converter<Saml2AuthenticationToken, Decrypter> {
		private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
				asList(
						new InlineEncryptedKeyResolver(),
						new EncryptedElementTypeEncryptedKeyResolver(),
						new SimpleRetrievalMethodEncryptedKeyResolver()
				)
		);

		@Override
		public Decrypter convert(Saml2AuthenticationToken token) {
			Collection<Credential> credentials = new ArrayList<>();
			for (Saml2X509Credential key : token.getRelyingPartyRegistration().getDecryptionX509Credentials()) {
				Credential cred = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
				credentials.add(cred);
			}
			KeyInfoCredentialResolver resolver = new CollectionKeyInfoCredentialResolver(credentials);
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

	/**
	 * A tuple containing an OpenSAML {@link Assertion} and its associated authentication token.
	 *
	 * @since 5.4
	 */
	public static class AssertionToken {
		private final Saml2AuthenticationToken token;
		private final Assertion assertion;

		private AssertionToken(Assertion assertion, Saml2AuthenticationToken token) {
			this.token = token;
			this.assertion = assertion;
		}

		public Assertion getAssertion() {
			return this.assertion;
		}

		public Saml2AuthenticationToken getToken() {
			return this.token;
		}
	}
}
