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
import java.util.function.Consumer;

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
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
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
import org.opensaml.saml.saml2.core.EncryptedAttribute;
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
import org.springframework.core.log.LogMessage;
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
 * @author Ryan Cassar
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

	private Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor = ((a) -> Collections
			.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

	private GrantedAuthoritiesMapper authoritiesMapper = ((a) -> a);

	private Duration responseTimeValidationSkew = Duration.ofMinutes(5);

	private Converter<ResponseToken, Saml2ResponseValidatorResult> responseSignatureValidator = createDefaultResponseSignatureValidator();

	private Consumer<ResponseToken> responseElementsDecrypter = createDefaultResponseElementsDecrypter();

	private Converter<ResponseToken, Saml2ResponseValidatorResult> responseValidator = createDefaultResponseValidator();

	private Converter<AssertionToken, Saml2ResponseValidatorResult> assertionSignatureValidator = createDefaultAssertionSignatureValidator();

	private Consumer<AssertionToken> assertionElementsDecrypter = createDefaultAssertionElementsDecrypter();

	private Converter<AssertionToken, Saml2ResponseValidatorResult> assertionValidator = createCompatibleAssertionValidator();

	private Converter<ResponseToken, ? extends AbstractAuthenticationToken> responseAuthenticationConverter = createCompatibleResponseAuthenticationConverter();

	private Converter<Saml2AuthenticationToken, SignatureTrustEngine> signatureTrustEngineConverter = new SignatureTrustEngineConverter();

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
	 * Set the {@link Consumer} strategy to use for decrypting elements of a validated
	 * {@link Response}. The default strategy decrypts all {@link EncryptedAssertion}s
	 * using OpenSAML's {@link Decrypter}, adding the results to
	 * {@link Response#getAssertions()}.
	 *
	 * You can use this method to configure the {@link Decrypter} instance like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	provider.setResponseElementsDecrypter((responseToken) -> {
	 *	    DecrypterParameters parameters = new DecrypterParameters();
	 *	    // ... set parameters as needed
	 *	    Decrypter decrypter = new Decrypter(parameters);
	 *		Response response = responseToken.getResponse();
	 *  	EncryptedAssertion encrypted = response.getEncryptedAssertions().get(0);
	 *  	try {
	 *  		Assertion assertion = decrypter.decrypt(encrypted);
	 *  		response.getAssertions().add(assertion);
	 *  	} catch (Exception e) {
	 *  	 	throw new Saml2AuthenticationException(...);
	 *  	}
	 *	});
	 * </pre>
	 *
	 * Or, in the event that you have your own custom decryption interface, the same
	 * pattern applies:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	Converter&lt;EncryptedAssertion, Assertion&gt; myService = ...
	 *	provider.setResponseDecrypter((responseToken) -> {
	 *	   Response response = responseToken.getResponse();
	 *	   response.getEncryptedAssertions().stream()
	 *	   		.map(service::decrypt).forEach(response.getAssertions()::add);
	 *	});
	 * </pre>
	 *
	 * This is valuable when using an external service to perform the decryption.
	 * @param responseElementsDecrypter the {@link Consumer} for decrypting response
	 * elements
	 * @since 5.5
	 */
	public void setResponseElementsDecrypter(Consumer<ResponseToken> responseElementsDecrypter) {
		Assert.notNull(responseElementsDecrypter, "responseElementsDecrypter cannot be null");
		this.responseElementsDecrypter = responseElementsDecrypter;
	}

	/**
	 * Set the {@link Converter} to use for validating each {@link Assertion} in the SAML
	 * 2.0 Response.
	 *
	 * You can still invoke the default validator by delgating to
	 * {@link #createAssertionValidator}, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *  provider.setAssertionValidator(assertionToken -> {
	 *		Saml2ResponseValidatorResult result = createDefaultAssertionValidator()
	 *			.convert(assertionToken)
	 *		return result.concat(myCustomValidator.convert(assertionToken));
	 *  });
	 * </pre>
	 *
	 * You can also use this method to configure the provider to use a different
	 * {@link ValidationContext} from the default, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	provider.setAssertionValidator(
	 *		createDefaultAssertionValidator(assertionToken -> {
	 *			Map&lt;String, Object&gt; params = new HashMap&lt;&gt;();
	 *			params.put(CLOCK_SKEW, 2 * 60 * 1000);
	 *			// other parameters
	 *			return new ValidationContext(params);
	 *		}));
	 * </pre>
	 *
	 * Consider taking a look at {@link #createValidationContext} to see how it constructs
	 * a {@link ValidationContext}.
	 *
	 * It is not necessary to delegate to the default validator. You can safely replace it
	 * entirely with your own. Note that signature verification is performed as a separate
	 * step from this validator.
	 *
	 * This method takes precedence over {@link #setResponseTimeValidationSkew}.
	 * @param assertionValidator
	 * @since 5.4
	 */
	public void setAssertionValidator(Converter<AssertionToken, Saml2ResponseValidatorResult> assertionValidator) {
		Assert.notNull(assertionValidator, "assertionValidator cannot be null");
		this.assertionValidator = assertionValidator;
	}

	/**
	 * Set the {@link Consumer} strategy to use for decrypting elements of a validated
	 * {@link Assertion}.
	 *
	 * You can use this method to configure the {@link Decrypter} used like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	provider.setResponseDecrypter((assertionToken) -> {
	 *	    DecrypterParameters parameters = new DecrypterParameters();
	 *	    // ... set parameters as needed
	 *	    Decrypter decrypter = new Decrypter(parameters);
	 *		Assertion assertion = assertionToken.getAssertion();
	 *  	EncryptedID encrypted = assertion.getSubject().getEncryptedID();
	 *  	try {
	 *  		NameID name = decrypter.decrypt(encrypted);
	 *  		assertion.getSubject().setNameID(name);
	 *  	} catch (Exception e) {
	 *  	 	throw new Saml2AuthenticationException(...);
	 *  	}
	 *	});
	 * </pre>
	 *
	 * Or, in the event that you have your own custom interface, the same pattern applies:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	MyDecryptionService myService = ...
	 *	provider.setResponseDecrypter((responseToken) -> {
	 *	   	Assertion assertion = assertionToken.getAssertion();
	 *	   	EncryptedID encrypted = assertion.getSubject().getEncryptedID();
	 *		NameID name = myService.decrypt(encrypted);
	 *		assertion.getSubject().setNameID(name);
	 *	});
	 * </pre>
	 * @param assertionDecrypter the {@link Consumer} for decrypting assertion elements
	 * @since 5.5
	 */
	public void setAssertionElementsDecrypter(Consumer<AssertionToken> assertionDecrypter) {
		Assert.notNull(assertionDecrypter, "assertionDecrypter cannot be null");
		this.assertionElementsDecrypter = assertionDecrypter;
	}

	/**
	 * Set the {@link Converter} to use for converting a validated {@link Response} into
	 * an {@link AbstractAuthenticationToken}.
	 *
	 * You can delegate to the default behavior by calling
	 * {@link #createDefaultResponseAuthenticationConverter()} like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 * 	Converter&lt;ResponseToken, Saml2Authentication&gt; authenticationConverter =
	 * 			createDefaultResponseAuthenticationConverter();
	 *	provider.setResponseAuthenticationConverter(responseToken -> {
	 *		Saml2Authentication authentication = authenticationConverter.convert(responseToken);
	 *		User user = myUserRepository.findByUsername(authentication.getName());
	 *		return new MyAuthentication(authentication, user);
	 *	});
	 * </pre>
	 *
	 * This method takes precedence over {@link #setAuthoritiesExtractor(Converter)} and
	 * {@link #setAuthoritiesMapper(GrantedAuthoritiesMapper)}.
	 * @param responseAuthenticationConverter the {@link Converter} to use
	 * @since 5.4
	 */
	public void setResponseAuthenticationConverter(
			Converter<ResponseToken, ? extends AbstractAuthenticationToken> responseAuthenticationConverter) {
		Assert.notNull(responseAuthenticationConverter, "responseAuthenticationConverter cannot be null");
		this.responseAuthenticationConverter = responseAuthenticationConverter;
	}

	/**
	 * Sets the {@link Converter} used for extracting assertion attributes that can be
	 * mapped to authorities.
	 * @param authoritiesExtractor the {@code Converter} used for mapping the assertion
	 * attributes to authorities
	 * @deprecated Use {@link #setResponseAuthenticationConverter(Converter)} instead
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
	 * @deprecated Use {@link #setResponseAuthenticationConverter(Converter)} instead
	 */
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * Sets the duration for how much time skew an assertion may tolerate during
	 * timestamp, NotOnOrBefore and NotOnOrAfter, validation.
	 * @param responseTimeValidationSkew duration for skew tolerance
	 * @deprecated Use {@link #setAssertionValidator(Converter)} instead
	 */
	public void setResponseTimeValidationSkew(Duration responseTimeValidationSkew) {
		this.responseTimeValidationSkew = responseTimeValidationSkew;
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @return the default assertion validator strategy
	 * @since 5.4
	 */
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator() {

		return createAssertionValidator(Saml2ErrorCodes.INVALID_ASSERTION,
				(assertionToken) -> SAML20AssertionValidators.attributeValidator,
				(assertionToken) -> createValidationContext(assertionToken, (params) -> {
				}));
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @param contextConverter the conversion strategy to use to generate a
	 * {@link ValidationContext} for each assertion being validated
	 * @return the default assertion validator strategy
	 * @since 5.4
	 */
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator(
			Converter<AssertionToken, ValidationContext> contextConverter) {

		return createAssertionValidator(Saml2ErrorCodes.INVALID_ASSERTION,
				(assertionToken) -> SAML20AssertionValidators.attributeValidator, contextConverter);
	}

	/**
	 * Construct a default strategy for converting a SAML 2.0 Response and
	 * {@link Authentication} token into a {@link Saml2Authentication}
	 * @return the default response authentication converter strategy
	 * @since 5.4
	 */
	public static Converter<ResponseToken, Saml2Authentication> createDefaultResponseAuthenticationConverter() {
		return (responseToken) -> {
			Saml2AuthenticationToken token = responseToken.token;
			Response response = responseToken.response;
			Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
			String username = assertion.getSubject().getNameID().getValue();
			Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
			return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal(username, attributes),
					token.getSaml2Response(), Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
		};
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
			return this.responseAuthenticationConverter.convert(new ResponseToken(response, token));
		}
		catch (Saml2AuthenticationException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw createAuthenticationException(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, ex.getMessage(), ex);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication != null && Saml2AuthenticationToken.class.isAssignableFrom(authentication);
	}

	private Response parse(String response) throws Saml2Exception, Saml2AuthenticationException {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (Response) this.responseUnmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw createAuthenticationException(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, ex.getMessage(), ex);
		}
	}

	private void process(Saml2AuthenticationToken token, Response response) {
		String issuer = response.getIssuer().getValue();
		logger.debug(LogMessage.format("Processing SAML response from %s", issuer));
		boolean responseSigned = response.isSigned();

		ResponseToken responseToken = new ResponseToken(response, token);
		Saml2ResponseValidatorResult result = this.responseSignatureValidator.convert(responseToken);
		if (responseSigned) {
			this.responseElementsDecrypter.accept(responseToken);
		}
		result = result.concat(this.responseValidator.convert(responseToken));
		boolean allAssertionsSigned = true;
		for (Assertion assertion : response.getAssertions()) {
			AssertionToken assertionToken = new AssertionToken(assertion, token);
			result = result.concat(this.assertionSignatureValidator.convert(assertionToken));
			allAssertionsSigned = allAssertionsSigned && assertion.isSigned();
			if (responseSigned || assertion.isSigned()) {
				this.assertionElementsDecrypter.accept(new AssertionToken(assertion, token));
			}
			result = result.concat(this.assertionValidator.convert(assertionToken));
		}
		if (!responseSigned && !allAssertionsSigned) {
			String description = "Either the response or one of the assertions is unsigned. "
					+ "Please either sign the response or all of the assertions.";
			throw createAuthenticationException(Saml2ErrorCodes.INVALID_SIGNATURE, description, null);
		}
		Assertion firstAssertion = CollectionUtils.firstElement(response.getAssertions());
		if (!hasName(firstAssertion)) {
			Saml2Error error = new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND,
					"Assertion [" + firstAssertion.getID() + "] is missing a subject");
			result = result.concat(error);
		}

		if (result.hasErrors()) {
			Collection<Saml2Error> errors = result.getErrors();
			if (logger.isTraceEnabled()) {
				logger.debug("Found " + errors.size() + " validation errors in SAML response [" + response.getID()
						+ "]: " + errors);
			}
			else if (logger.isDebugEnabled()) {
				logger.debug(
						"Found " + errors.size() + " validation errors in SAML response [" + response.getID() + "]");
			}
			Saml2Error first = errors.iterator().next();
			throw createAuthenticationException(first.getErrorCode(), first.getDescription(), null);
		}
		else {
			if (logger.isDebugEnabled()) {
				logger.debug("Successfully processed SAML Response [" + response.getID() + "]");
			}
		}
	}

	private Converter<ResponseToken, Saml2ResponseValidatorResult> createDefaultResponseSignatureValidator() {
		return (responseToken) -> {
			Response response = responseToken.getResponse();
			Saml2AuthenticationToken token = responseToken.getToken();
			Collection<Saml2Error> errors = new ArrayList<>();
			String issuer = response.getIssuer().getValue();
			if (response.isSigned()) {
				SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
				try {
					profileValidator.validate(response.getSignature());
				}
				catch (Exception ex) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for SAML Response [" + response.getID() + "]: "));
				}

				try {
					CriteriaSet criteriaSet = new CriteriaSet();
					criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
					criteriaSet.add(new EvaluableProtocolRoleDescriptorCriterion(
							new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
					criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
					if (!this.signatureTrustEngineConverter.convert(token).validate(response.getSignature(),
							criteriaSet)) {
						errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
								"Invalid signature for SAML Response [" + response.getID() + "]"));
					}
				}
				catch (Exception ex) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for SAML Response [" + response.getID() + "]: "));
				}
			}

			return Saml2ResponseValidatorResult.failure(errors);
		};
	}

	private Consumer<ResponseToken> createDefaultResponseElementsDecrypter() {
		return (responseToken) -> {
			Decrypter decrypter = this.decrypterConverter.convert(responseToken.getToken());
			Response response = responseToken.getResponse();
			for (EncryptedAssertion encryptedAssertion : responseToken.getResponse().getEncryptedAssertions()) {
				try {
					Assertion assertion = decrypter.decrypt(encryptedAssertion);
					response.getAssertions().add(assertion);
				}
				catch (Exception ex) {
					throw createAuthenticationException(Saml2ErrorCodes.DECRYPTION_ERROR, ex.getMessage(), ex);
				}
			}
		};
	}

	private Converter<ResponseToken, Saml2ResponseValidatorResult> createDefaultResponseValidator() {
		return (responseToken) -> {
			Response response = responseToken.getResponse();
			Saml2AuthenticationToken token = responseToken.getToken();
			Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
			String issuer = response.getIssuer().getValue();
			String destination = response.getDestination();
			String location = token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
			if (StringUtils.hasText(destination) && !destination.equals(location)) {
				String message = "Invalid destination [" + destination + "] for SAML response [" + response.getID()
						+ "]";
				result = result.concat(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION, message));
			}
			String assertingPartyEntityId = token.getRelyingPartyRegistration().getAssertingPartyDetails()
					.getEntityId();
			if (!StringUtils.hasText(issuer) || !issuer.equals(assertingPartyEntityId)) {
				String message = String.format("Invalid issuer [%s] for SAML response [%s]", issuer, response.getID());
				result = result.concat(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, message));
			}
			if (response.getAssertions().isEmpty()) {
				throw createAuthenticationException(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA,
						"No assertions found in response.", null);
			}
			return result;
		};
	}

	private Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionSignatureValidator() {
		return createAssertionValidator(Saml2ErrorCodes.INVALID_SIGNATURE, (assertionToken) -> {
			SignatureTrustEngine engine = this.signatureTrustEngineConverter.convert(assertionToken.token);
			return SAML20AssertionValidators.createSignatureValidator(engine);
		}, (assertionToken) -> new ValidationContext(
				Collections.singletonMap(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false)));
	}

	private Consumer<AssertionToken> createDefaultAssertionElementsDecrypter() {
		return (assertionToken) -> {
			Decrypter decrypter = this.decrypterConverter.convert(assertionToken.getToken());
			Assertion assertion = assertionToken.getAssertion();
			for (AttributeStatement statement : assertion.getAttributeStatements()) {
				for (EncryptedAttribute encryptedAttribute : statement.getEncryptedAttributes()) {
					try {
						Attribute attribute = decrypter.decrypt(encryptedAttribute);
						statement.getAttributes().add(attribute);
					}
					catch (Exception ex) {
						throw createAuthenticationException(Saml2ErrorCodes.DECRYPTION_ERROR, ex.getMessage(), ex);
					}
				}
			}
			if (assertion.getSubject() == null) {
				return;
			}
			if (assertion.getSubject().getEncryptedID() == null) {
				return;
			}
			try {
				assertion.getSubject().setNameID((NameID) decrypter.decrypt(assertion.getSubject().getEncryptedID()));
			}
			catch (Exception ex) {
				throw createAuthenticationException(Saml2ErrorCodes.DECRYPTION_ERROR, ex.getMessage(), ex);
			}
		};
	}

	private Converter<AssertionToken, Saml2ResponseValidatorResult> createCompatibleAssertionValidator() {
		return createAssertionValidator(Saml2ErrorCodes.INVALID_ASSERTION,
				(assertionToken) -> SAML20AssertionValidators.attributeValidator,
				(assertionToken) -> createValidationContext(assertionToken,
						(params) -> params.put(SAML2AssertionValidationParameters.CLOCK_SKEW,
								this.responseTimeValidationSkew.toMillis())));
	}

	private Converter<ResponseToken, Saml2Authentication> createCompatibleResponseAuthenticationConverter() {
		return (responseToken) -> {
			Response response = responseToken.response;
			Saml2AuthenticationToken token = responseToken.token;
			Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
			String username = assertion.getSubject().getNameID().getValue();
			Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
			return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal(username, attributes),
					token.getSaml2Response(),
					this.authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion)));
		};
	}

	private Collection<? extends GrantedAuthority> getAssertionAuthorities(Assertion assertion) {
		return this.authoritiesExtractor.convert(assertion);
	}

	private boolean hasName(Assertion assertion) {
		if (assertion == null) {
			return false;
		}
		if (assertion.getSubject() == null) {
			return false;
		}
		if (assertion.getSubject().getNameID() == null) {
			return false;
		}
		return assertion.getSubject().getNameID().getValue() != null;
	}

	private static Map<String, List<Object>> getAssertionAttributes(Assertion assertion) {
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

	private static Object getXmlObjectValue(XMLObject xmlObject) {
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
			return (xsBooleanValue != null) ? xsBooleanValue.getValue() : null;
		}
		if (xmlObject instanceof XSDateTime) {
			DateTime dateTime = ((XSDateTime) xmlObject).getValue();
			return (dateTime != null) ? Instant.ofEpochMilli(dateTime.getMillis()) : null;
		}
		return null;
	}

	private static Saml2AuthenticationException createAuthenticationException(String code, String message,
			Exception cause) {
		return new Saml2AuthenticationException(new Saml2Error(code, message), cause);
	}

	private static Converter<AssertionToken, Saml2ResponseValidatorResult> createAssertionValidator(String errorCode,
			Converter<AssertionToken, SAML20AssertionValidator> validatorConverter,
			Converter<AssertionToken, ValidationContext> contextConverter) {

		return (assertionToken) -> {
			Assertion assertion = assertionToken.assertion;
			SAML20AssertionValidator validator = validatorConverter.convert(assertionToken);
			ValidationContext context = contextConverter.convert(assertionToken);
			try {
				ValidationResult result = validator.validate(assertion, context);
				if (result == ValidationResult.VALID) {
					return Saml2ResponseValidatorResult.success();
				}
			}
			catch (Exception ex) {
				String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
						((Response) assertion.getParent()).getID(), ex.getMessage());
				return Saml2ResponseValidatorResult.failure(new Saml2Error(errorCode, message));
			}
			String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
					((Response) assertion.getParent()).getID(), context.getValidationFailureMessage());
			return Saml2ResponseValidatorResult.failure(new Saml2Error(errorCode, message));
		};
	}

	private static ValidationContext createValidationContext(AssertionToken assertionToken,
			Consumer<Map<String, Object>> paramsConsumer) {
		String audience = assertionToken.token.getRelyingPartyRegistration().getEntityId();
		String recipient = assertionToken.token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
		Map<String, Object> params = new HashMap<>();
		params.put(SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, Collections.singleton(audience));
		params.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton(recipient));
		paramsConsumer.accept(params);
		return new ValidationContext(params);
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

		private static final SAML20AssertionValidator attributeValidator = new SAML20AssertionValidator(conditions,
				subjects, statements, null, null) {
			@Nonnull
			@Override
			protected ValidationResult validateSignature(Assertion token, ValidationContext context) {
				return ValidationResult.VALID;
			}
		};

		static SAML20AssertionValidator createSignatureValidator(SignatureTrustEngine engine) {
			return new SAML20AssertionValidator(new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), engine,
					validator) {
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
	 * A tuple containing an OpenSAML {@link Response} and its associated authentication
	 * token.
	 *
	 * @since 5.4
	 */
	public static class ResponseToken {

		private final Saml2AuthenticationToken token;

		private final Response response;

		ResponseToken(Response response, Saml2AuthenticationToken token) {
			this.token = token;
			this.response = response;
		}

		public Response getResponse() {
			return this.response;
		}

		public Saml2AuthenticationToken getToken() {
			return this.token;
		}

	}

	/**
	 * A tuple containing an OpenSAML {@link Assertion} and its associated authentication
	 * token.
	 *
	 * @since 5.4
	 */
	public static class AssertionToken {

		private final Saml2AuthenticationToken token;

		private final Assertion assertion;

		AssertionToken(Assertion assertion, Saml2AuthenticationToken token) {
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
