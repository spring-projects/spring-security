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
import java.util.Arrays;
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

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
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
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.NameID;
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
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Implementation of {@link AuthenticationProvider} for SAML authentications when
 * receiving a {@code Response} object containing an {@code Assertion}. This
 * implementation uses the {@code OpenSAML 3} library.
 *
 * <p>
 * The {@link OpenSamlAuthenticationProvider} supports {@link Saml2AuthenticationToken}
 * objects that contain a SAML response in its decoded XML format
 * {@link Saml2AuthenticationToken#getSaml2Response()} along with the information about
 * the asserting party, the identity provider (IDP), as well as the relying party, the
 * service provider (SP, this application).
 * </p>
 * <p>
 * The {@link Saml2AuthenticationToken} will be processed into a SAML Response object. The
 * SAML response object can be signed. If the Response is signed, a signature will not be
 * required on the assertion.
 * </p>
 * <p>
 * While a response object can contain a list of assertion, this provider will only
 * leverage the first valid assertion for the purpose of authentication. Assertions that
 * do not pass validation will be ignored. If no valid assertions are found a
 * {@link Saml2AuthenticationException} is thrown.
 * </p>
 * <p>
 * This provider supports two types of encrypted SAML elements
 * <ul>
 * <li><a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=17">EncryptedAssertion</a></li>
 * <li><a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=14">EncryptedID</a></li>
 * </ul>
 * If the assertion is encrypted, then signature validation on the assertion is no longer
 * required.
 * </p>
 * <p>
 * This provider does not perform an X509 certificate validation on the configured
 * asserting party, IDP, verification certificates.
 * </p>
 *
 * @since 5.2
 * @see <a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=38">SAML 2
 * StatusResponse</a>
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

	private Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor = (a -> Collections
			.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

	private GrantedAuthoritiesMapper authoritiesMapper = (a -> a);

	private Duration responseTimeValidationSkew = Duration.ofMinutes(5);

	private Function<Saml2AuthenticationToken, Converter<Response, AbstractAuthenticationToken>> authenticationConverter = token -> response -> {
		Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
		String username = assertion.getSubject().getNameID().getValue();
		Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
		return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal(username, attributes),
				token.getSaml2Response(), this.authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion)));
	};

	private Converter<Saml2AuthenticationToken, SignatureTrustEngine> signatureTrustEngineConverter = new SignatureTrustEngineConverter();

	private Converter<Tuple, SAML20AssertionValidator> assertionValidatorConverter = new SAML20AssertionValidatorConverter();

	private Collection<ConditionValidator> conditionValidators = Collections
			.singleton(new AudienceRestrictionConditionValidator());

	private Converter<Tuple, ValidationContext> validationContextConverter = new ValidationContextConverter();

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
	 * Set the the collection of {@link ConditionValidator}s used when validating an
	 * assertion.
	 * @param conditionValidators the collection of validators to use
	 * @since 5.4
	 */
	public void setConditionValidators(Collection<ConditionValidator> conditionValidators) {

		Assert.notEmpty(conditionValidators, "conditionValidators cannot be empty");
		this.conditionValidators = conditionValidators;
	}

	/**
	 * Set the strategy for retrieving the {@link ValidationContext} used when validating
	 * an assertion.
	 * @param validationContextConverter the strategy to use
	 * @since 5.4
	 */
	public void setValidationContextConverter(Converter<Tuple, ValidationContext> validationContextConverter) {

		Assert.notNull(validationContextConverter, "validationContextConverter cannot be empty");
		this.validationContextConverter = validationContextConverter;
	}

	/**
	 * Sets the {@link Converter} used for extracting assertion attributes that can be
	 * mapped to authorities.
	 * @param authoritiesExtractor the {@code Converter} used for mapping the assertion
	 * attributes to authorities
	 */
	public void setAuthoritiesExtractor(
			Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor) {
		Assert.notNull(authoritiesExtractor, "authoritiesExtractor cannot be null");
		this.authoritiesExtractor = authoritiesExtractor;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for mapping assertion attributes to
	 * a new set of authorities which will be associated to the
	 * {@link Saml2Authentication}. Note: This implementation is only retrieving
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the
	 * user's authorities
	 */
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
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
	 * {@link Saml2AuthenticationToken}
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
		}
		catch (Saml2AuthenticationException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw authException(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, ex.getMessage(), ex);
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
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (Response) this.responseUnmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw authException(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, ex.getMessage(), ex);
		}
	}

	private void process(Saml2AuthenticationToken token, Response response) {
		String issuer = response.getIssuer().getValue();
		if (logger.isDebugEnabled()) {
			logger.debug("Processing SAML response from " + issuer);
		}

		boolean responseSigned = response.isSigned();
		Map<String, Saml2AuthenticationException> validationExceptions = validateResponse(token, response);

		Decrypter decrypter = this.decrypterConverter.convert(token);
		List<Assertion> assertions = decryptAssertions(decrypter, response);
		if (!isSigned(responseSigned, assertions)) {
			throw authException(Saml2ErrorCodes.INVALID_SIGNATURE,
					"Either the response or one of the assertions is unsigned. "
							+ "Please either sign the response or all of the assertions.");
		}
		validationExceptions.putAll(validateAssertions(token, response));

		Assertion firstAssertion = CollectionUtils.firstElement(response.getAssertions());
		NameID nameId = decryptPrincipal(decrypter, firstAssertion);
		if (nameId == null || nameId.getValue() == null) {
			validationExceptions.put(Saml2ErrorCodes.SUBJECT_NOT_FOUND, authException(Saml2ErrorCodes.SUBJECT_NOT_FOUND,
					"Assertion [" + firstAssertion.getID() + "] is missing a subject"));
		}

		if (validationExceptions.isEmpty()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Successfully processed SAML Response [" + response.getID() + "]");
			}
		}
		else {
			if (logger.isTraceEnabled()) {
				logger.debug("Found " + validationExceptions.size() + " validation errors in SAML response ["
						+ response.getID() + "]: " + validationExceptions.values());
			}
			else if (logger.isDebugEnabled()) {
				logger.debug("Found " + validationExceptions.size() + " validation errors in SAML response ["
						+ response.getID() + "]");
			}
		}

		if (!validationExceptions.isEmpty()) {
			throw validationExceptions.values().iterator().next();
		}
	}

	private Map<String, Saml2AuthenticationException> validateResponse(Saml2AuthenticationToken token,
			Response response) {

		Map<String, Saml2AuthenticationException> validationExceptions = new HashMap<>();
		String issuer = response.getIssuer().getValue();

		if (response.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(response.getSignature());
			}
			catch (Exception ex) {
				validationExceptions.put(Saml2ErrorCodes.INVALID_SIGNATURE,
						authException(Saml2ErrorCodes.INVALID_SIGNATURE,
								"Invalid signature for SAML Response [" + response.getID() + "]: ", ex));
			}

			try {
				CriteriaSet criteriaSet = new CriteriaSet();
				criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
				criteriaSet.add(
						new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
				criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
				if (!this.signatureTrustEngineConverter.convert(token).validate(response.getSignature(), criteriaSet)) {
					validationExceptions.put(Saml2ErrorCodes.INVALID_SIGNATURE,
							authException(Saml2ErrorCodes.INVALID_SIGNATURE,
									"Invalid signature for SAML Response [" + response.getID() + "]"));
				}
			}
			catch (Exception ex) {
				validationExceptions.put(Saml2ErrorCodes.INVALID_SIGNATURE,
						authException(Saml2ErrorCodes.INVALID_SIGNATURE,
								"Invalid signature for SAML Response [" + response.getID() + "]: ", ex));
			}
		}

		String destination = response.getDestination();
		String location = token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
		if (StringUtils.hasText(destination) && !destination.equals(location)) {
			String message = "Invalid destination [" + destination + "] for SAML response [" + response.getID() + "]";
			validationExceptions.put(Saml2ErrorCodes.INVALID_DESTINATION,
					authException(Saml2ErrorCodes.INVALID_DESTINATION, message));
		}

		String assertingPartyEntityId = token.getRelyingPartyRegistration().getAssertingPartyDetails().getEntityId();
		if (!StringUtils.hasText(issuer) || !issuer.equals(assertingPartyEntityId)) {
			String message = String.format("Invalid issuer [%s] for SAML response [%s]", issuer, response.getID());
			validationExceptions.put(Saml2ErrorCodes.INVALID_ISSUER,
					authException(Saml2ErrorCodes.INVALID_ISSUER, message));
		}

		return validationExceptions;
	}

	private List<Assertion> decryptAssertions(Decrypter decrypter, Response response) {
		List<Assertion> assertions = new ArrayList<>();
		for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
			try {
				Assertion assertion = decrypter.decrypt(encryptedAssertion);
				assertions.add(assertion);
			}
			catch (DecryptionException ex) {
				throw authException(Saml2ErrorCodes.DECRYPTION_ERROR, ex.getMessage(), ex);
			}
		}
		response.getAssertions().addAll(assertions);
		return response.getAssertions();
	}

	private Map<String, Saml2AuthenticationException> validateAssertions(Saml2AuthenticationToken token,
			Response response) {
		List<Assertion> assertions = response.getAssertions();
		if (assertions.isEmpty()) {
			throw authException(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response.");
		}

		Map<String, Saml2AuthenticationException> validationExceptions = new LinkedHashMap<>();
		if (logger.isDebugEnabled()) {
			logger.debug("Validating " + assertions.size() + " assertions");
		}

		Tuple tuple = new Tuple(token, response);
		SAML20AssertionValidator validator = this.assertionValidatorConverter.convert(tuple);
		ValidationContext context = this.validationContextConverter.convert(tuple);
		for (Assertion assertion : assertions) {
			if (logger.isTraceEnabled()) {
				logger.trace("Validating assertion " + assertion.getID());
			}
			try {
				if (validator.validate(assertion, context) != ValidationResult.VALID) {
					String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s",
							assertion.getID(), ((Response) assertion.getParent()).getID(),
							context.getValidationFailureMessage());
					validationExceptions.put(Saml2ErrorCodes.INVALID_ASSERTION,
							authException(Saml2ErrorCodes.INVALID_ASSERTION, message));
				}
			}
			catch (Exception ex) {
				String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
						((Response) assertion.getParent()).getID(), ex.getMessage());
				validationExceptions.put(Saml2ErrorCodes.INVALID_ASSERTION,
						authException(Saml2ErrorCodes.INVALID_ASSERTION, message, ex));
			}
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
		}
		catch (DecryptionException ex) {
			throw authException(Saml2ErrorCodes.DECRYPTION_ERROR, ex.getMessage(), ex);
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
		Marshaller marshaller = this.registry.getMarshallerFactory().getMarshaller(xsAny);
		if (marshaller != null) {
			try {
				Element element = marshaller.marshall(xsAny);
				return SerializeSupport.nodeToString(element);
			}
			catch (MarshallingException ex) {
				throw new Saml2Exception(ex);
			}
		}
		return xsAny.getTextContent();
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

	private static class SignatureTrustEngineConverter
			implements Converter<Saml2AuthenticationToken, SignatureTrustEngine> {

		@Override
		public SignatureTrustEngine convert(Saml2AuthenticationToken token) {
			Set<Credential> credentials = new HashSet<>();
			Collection<Saml2X509Credential> keys = token.getRelyingPartyRegistration().getAssertingPartyDetails()
					.getVerificationX509Credentials();
			for (Saml2X509Credential key : keys) {
				BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
				cred.setUsageType(UsageType.SIGNING);
				cred.setEntityId(token.getRelyingPartyRegistration().getAssertingPartyDetails().getEntityId());
				credentials.add(cred);
			}
			CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
			return new ExplicitKeySignatureTrustEngine(credentialsResolver,
					DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
		}

	}

	private class ValidationContextConverter implements Converter<Tuple, ValidationContext> {

		@Override
		public ValidationContext convert(Tuple tuple) {
			String audience = tuple.authentication.getRelyingPartyRegistration().getEntityId();
			String recipient = tuple.authentication.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
			Map<String, Object> params = new HashMap<>();
			params.put(SAML2AssertionValidationParameters.CLOCK_SKEW,
					OpenSamlAuthenticationProvider.this.responseTimeValidationSkew.toMillis());
			params.put(SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, Collections.singleton(audience));
			params.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton(recipient));
			params.put(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false); // this
																						// verification
																						// is
																						// performed
			// earlier
			return new ValidationContext(params);
		}

	}

	private class SAML20AssertionValidatorConverter implements Converter<Tuple, SAML20AssertionValidator> {

		private final Collection<SubjectConfirmationValidator> subjects = new ArrayList<>();

		private final Collection<StatementValidator> statements = new ArrayList<>();

		private final SignaturePrevalidator validator = new SAMLSignatureProfileValidator();

		SAML20AssertionValidatorConverter() {
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

		@Override
		public SAML20AssertionValidator convert(Tuple tuple) {
			Collection<ConditionValidator> conditions = OpenSamlAuthenticationProvider.this.conditionValidators;
			return new SAML20AssertionValidator(conditions, this.subjects, this.statements,
					OpenSamlAuthenticationProvider.this.signatureTrustEngineConverter.convert(tuple.authentication),
					this.validator);
		}

	}

	private static class DecrypterConverter implements Converter<Saml2AuthenticationToken, Decrypter> {

		private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
				Arrays.asList(new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(),
						new SimpleRetrievalMethodEncryptedKeyResolver()));

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

	/**
	 * A tuple containing the authentication token and the associated OpenSAML
	 * {@link Response}.
	 *
	 * @since 5.4
	 */
	public static final class Tuple {

		private final Saml2AuthenticationToken authentication;

		private final Response response;

		private Tuple(Saml2AuthenticationToken authentication, Response response) {
			this.authentication = authentication;
			this.response = response;
		}

		public Saml2AuthenticationToken getAuthentication() {
			return this.authentication;
		}

		public Response getResponse() {
			return this.response;
		}

	}

}
