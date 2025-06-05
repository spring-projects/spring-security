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

package org.springframework.security.saml2.provider.service.authentication;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.saml2.assertion.ConditionValidator;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.DelegationRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.ProxyRestrictionConditionValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Implementation of {@link AuthenticationProvider} for SAML authentications when
 * receiving a {@code Response} object containing an {@code Assertion}. This
 * implementation uses the {@code OpenSAML 5} library.
 *
 * <p>
 * The {@link OpenSaml5AuthenticationProvider} supports {@link Saml2AuthenticationToken}
 * objects that contain a SAML response in its decoded XML format
 * {@link Saml2AuthenticationToken#getSaml2Response()} along with the information about
 * the asserting party, the identity provider (IDP), as well as the relying party, the
 * service provider (SP, this application).
 * <p>
 * The {@link Saml2AuthenticationToken} will be processed into a SAML Response object. The
 * SAML response object can be signed. If the Response is signed, a signature will not be
 * required on the assertion.
 * <p>
 * While a response object can contain a list of assertion, this provider will only
 * leverage the first valid assertion for the purpose of authentication. Assertions that
 * do not pass validation will be ignored. If no valid assertions are found a
 * {@link Saml2AuthenticationException} is thrown.
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
 * <p>
 * This provider does not perform an X509 certificate validation on the configured
 * asserting party, IDP, verification certificates.
 *
 * @author Josh Cummings
 * @since 5.5
 * @see <a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=38">SAML 2
 * StatusResponse</a>
 * @see <a href="https://shibboleth.atlassian.net/wiki/spaces/OSAML/overview">OpenSAML</a>
 */
public final class OpenSaml5AuthenticationProvider implements AuthenticationProvider {

	private final BaseOpenSamlAuthenticationProvider delegate;

	/**
	 * Creates an {@link OpenSaml5AuthenticationProvider}
	 */
	public OpenSaml5AuthenticationProvider() {
		this.delegate = new BaseOpenSamlAuthenticationProvider(new OpenSaml5Template());
		setResponseValidator(ResponseValidator.withDefaults());
		setAssertionValidator(AssertionValidator.withDefaults());
		setResponseAuthenticationConverter(new ResponseAuthenticationConverter());
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
	 *	provider.setResponseElementsDecrypter((responseToken) -&gt; {
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
	 *	provider.setResponseDecrypter((responseToken) -&gt; {
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
		this.delegate
			.setResponseElementsDecrypter((token) -> responseElementsDecrypter.accept(new ResponseToken(token)));
	}

	/**
	 * Set the {@link Converter} to use for validating the SAML 2.0 Response.
	 *
	 * You can still invoke the default validator by delegating to
	 * {@link #createDefaultResponseValidator()}, like so:
	 *
	 * <pre>
	 * OpenSaml5AuthenticationProvider provider = new OpenSaml5AuthenticationProvider();
	 * provider.setResponseValidator(responseToken -&gt; {
	 * 		Saml2ResponseValidatorResult result = createDefaultResponseValidator()
	 * 			.convert(responseToken)
	 * 		return result.concat(myCustomValidator.convert(responseToken));
	 * });
	 * </pre>
	 * @param responseValidator the {@link Converter} to use
	 * @since 5.6
	 */
	public void setResponseValidator(Converter<ResponseToken, Saml2ResponseValidatorResult> responseValidator) {
		Assert.notNull(responseValidator, "responseValidator cannot be null");
		this.delegate.setResponseValidator((token) -> responseValidator.convert(new ResponseToken(token)));
	}

	/**
	 * Set the {@link Converter} to use for validating each {@link Assertion} in the SAML
	 * 2.0 Response.
	 *
	 * You can still invoke the default validator by calling
	 * {@link AssertionValidator#withDefaults()}, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *  AssertionValidator validator = AssertionValidator.withDefaults();
	 *  provider.setAssertionValidator(assertionToken -&gt; {
	 *		Saml2ResponseValidatorResult result = validator.validate(assertionToken);
	 *		return result.concat(myCustomValidator.convert(assertionToken));
	 *  });
	 * </pre>
	 *
	 * You can also use this method to configure the provider to use a different
	 * {@link ValidationContext} from the default, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *  AssertionValidator validator = AssertionValidator.builder().clockSkew(Duration.ofMinutes(2)).build();
	 *	provider.setAssertionValidator(validator);
	 * </pre>
	 *
	 * Consider taking a look at {@link AssertionValidator#createValidationContext} to see
	 * how it constructs a {@link ValidationContext}.
	 *
	 * It is not necessary to delegate to the default validator. You can safely replace it
	 * entirely with your own. Note that signature verification is performed as a separate
	 * step from this validator.
	 * @param assertionValidator the validator to use
	 * @since 5.4
	 */
	public void setAssertionValidator(Converter<AssertionToken, Saml2ResponseValidatorResult> assertionValidator) {
		Assert.notNull(assertionValidator, "assertionValidator cannot be null");
		this.delegate.setAssertionValidator((token) -> assertionValidator.convert(new AssertionToken(token)));
	}

	/**
	 * Set the {@link Consumer} strategy to use for decrypting elements of a validated
	 * {@link Assertion}.
	 *
	 * You can use this method to configure the {@link Decrypter} used like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *	provider.setResponseDecrypter((assertionToken) -&gt; {
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
	 *	provider.setResponseDecrypter((responseToken) -&gt; {
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
		this.delegate.setAssertionElementsDecrypter((token) -> assertionDecrypter.accept(new AssertionToken(token)));
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
	 *	provider.setResponseAuthenticationConverter(responseToken -&gt; {
	 *		Saml2Authentication authentication = authenticationConverter.convert(responseToken);
	 *		User user = myUserRepository.findByUsername(authentication.getName());
	 *		return new MyAuthentication(authentication, user);
	 *	});
	 * </pre>
	 * @param responseAuthenticationConverter the {@link Converter} to use
	 * @since 5.4
	 */
	public void setResponseAuthenticationConverter(
			Converter<ResponseToken, ? extends AbstractAuthenticationToken> responseAuthenticationConverter) {
		Assert.notNull(responseAuthenticationConverter, "responseAuthenticationConverter cannot be null");
		this.delegate.setResponseAuthenticationConverter(
				(token) -> responseAuthenticationConverter.convert(new ResponseToken(token)));
	}

	/**
	 * Indicate when to validate response attributes, like {@code Destination} and
	 * {@code Issuer}. By default, this value is set to false, meaning that response
	 * attributes are validated first. Setting this value to {@code true} allows you to
	 * use a response authentication converter that doesn't rely on the {@code NameID}
	 * element in the {@link Response}'s assertion.
	 * @param validateResponseAfterAssertions when to validate response attributes
	 * @since 6.5
	 * @see #setResponseAuthenticationConverter
	 * @see ResponseAuthenticationConverter
	 */
	public void setValidateResponseAfterAssertions(boolean validateResponseAfterAssertions) {
		this.delegate.setValidateResponseAfterAssertions(validateResponseAfterAssertions);
	}

	/**
	 * Construct a default strategy for validating the SAML 2.0 Response
	 * @return the default response validator strategy
	 * @since 5.6
	 * @deprecated please use {@link ResponseValidator#withDefaults()} instead
	 */
	@Deprecated
	public static Converter<ResponseToken, Saml2ResponseValidatorResult> createDefaultResponseValidator() {
		return ResponseValidator.withDefaults();
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @return the default assertion validator strategy
	 * @deprecated please use {@link AssertionValidator#withDefaults()} instead
	 */
	@Deprecated
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator() {
		return AssertionValidator.withDefaults();
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @param contextConverter the conversion strategy to use to generate a
	 * {@link ValidationContext} for each assertion being validated
	 * @return the default assertion validator strategy
	 * @deprecated Use {@link #createDefaultAssertionValidatorWithParameters} instead
	 */
	@Deprecated
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator(
			Converter<AssertionToken, ValidationContext> contextConverter) {
		return (assertionToken) -> {
			Assertion assertion = assertionToken.getAssertion();
			SAML20AssertionValidator validator = BaseOpenSamlAuthenticationProvider.SAML20AssertionValidators.attributeValidator;
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
				return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ASSERTION, message));
			}
			String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
					((Response) assertion.getParent()).getID(), context.getValidationFailureMessages());
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ASSERTION, message));
		};
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @param validationContextParameters a consumer for editing the values passed to the
	 * {@link ValidationContext} for each assertion being validated
	 * @return the default assertion validator strategy
	 * @since 5.8
	 * @deprecated please use {@link AssertionValidator#withDefaults()} instead
	 */
	@Deprecated
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidatorWithParameters(
			Consumer<Map<String, Object>> validationContextParameters) {
		return AssertionValidator.builder().validationContextParameters(validationContextParameters).build();
	}

	/**
	 * Construct a default strategy for converting a SAML 2.0 Response and
	 * {@link Authentication} token into a {@link Saml2Authentication}
	 * @return the default response authentication converter strategy
	 * @deprecated please use {@link ResponseAuthenticationConverter} instead
	 */
	@Deprecated
	public static Converter<ResponseToken, Saml2Authentication> createDefaultResponseAuthenticationConverter() {
		return new ResponseAuthenticationConverter();
	}

	/**
	 * @param authentication the authentication request object, must be of type
	 * {@link Saml2AuthenticationToken}
	 * @return {@link Saml2Authentication} if the assertion is valid
	 * @throws AuthenticationException if a validation exception occurs
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		return this.delegate.authenticate(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication != null && Saml2AuthenticationToken.class.isAssignableFrom(authentication);
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

		ResponseToken(BaseOpenSamlAuthenticationProvider.ResponseToken token) {
			this.token = token.getToken();
			this.response = token.getResponse();
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

		AssertionToken(BaseOpenSamlAuthenticationProvider.AssertionToken token) {
			this.token = token.getToken();
			this.assertion = token.getAssertion();
		}

		public Assertion getAssertion() {
			return this.assertion;
		}

		public Saml2AuthenticationToken getToken() {
			return this.token;
		}

	}

	/**
	 * A response validator that checks the {@code InResponseTo} value against the
	 * correlating {@link AbstractSaml2AuthenticationRequest}
	 *
	 * @since 6.5
	 */
	public static final class InResponseToValidator implements Converter<ResponseToken, Saml2ResponseValidatorResult> {

		@Override
		@NonNull
		public Saml2ResponseValidatorResult convert(ResponseToken responseToken) {
			AbstractSaml2AuthenticationRequest request = responseToken.getToken().getAuthenticationRequest();
			Response response = responseToken.getResponse();
			String inResponseTo = response.getInResponseTo();
			return BaseOpenSamlAuthenticationProvider.validateInResponseTo(request, inResponseTo);
		}

	}

	/**
	 * A response validator that compares the {@code Destination} value to the configured
	 * {@link RelyingPartyRegistration#getAssertionConsumerServiceLocation()}
	 *
	 * @since 6.5
	 */
	public static final class DestinationValidator implements Converter<ResponseToken, Saml2ResponseValidatorResult> {

		@Override
		@NonNull
		public Saml2ResponseValidatorResult convert(ResponseToken responseToken) {
			Response response = responseToken.getResponse();
			Saml2AuthenticationToken token = responseToken.getToken();
			String destination = response.getDestination();
			String location = token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
			if (StringUtils.hasText(destination) && !destination.equals(location)) {
				String message = "Invalid destination [" + destination + "] for SAML response [" + response.getID()
						+ "]";
				return Saml2ResponseValidatorResult
					.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION, message));
			}
			return Saml2ResponseValidatorResult.success();
		}

	}

	/**
	 * A response validator that compares the {@code Issuer} value to the configured
	 * {@link AssertingPartyMetadata#getEntityId()}
	 *
	 * @since 6.5
	 */
	public static final class IssuerValidator implements Converter<ResponseToken, Saml2ResponseValidatorResult> {

		@Override
		@NonNull
		public Saml2ResponseValidatorResult convert(ResponseToken responseToken) {
			Response response = responseToken.getResponse();
			Saml2AuthenticationToken token = responseToken.getToken();
			String issuer = response.getIssuer().getValue();
			String assertingPartyEntityId = token.getRelyingPartyRegistration()
				.getAssertingPartyMetadata()
				.getEntityId();
			if (!StringUtils.hasText(issuer) || !issuer.equals(assertingPartyEntityId)) {
				String message = String.format("Invalid issuer [%s] for SAML response [%s]", issuer, response.getID());
				return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, message));
			}
			return Saml2ResponseValidatorResult.success();
		}

	}

	/**
	 * A composite response validator that confirms a {@code SUCCESS} status, that there
	 * is at least one assertion, and any other configured converters
	 *
	 * @since 6.5
	 * @see InResponseToValidator
	 * @see DestinationValidator
	 * @see IssuerValidator
	 */
	public static final class ResponseValidator implements Converter<ResponseToken, Saml2ResponseValidatorResult> {

		private static final List<Converter<ResponseToken, Saml2ResponseValidatorResult>> DEFAULTS = List
			.of(new InResponseToValidator(), new DestinationValidator(), new IssuerValidator());

		private final List<Converter<ResponseToken, Saml2ResponseValidatorResult>> validators;

		@SafeVarargs
		public ResponseValidator(Converter<ResponseToken, Saml2ResponseValidatorResult>... validators) {
			this.validators = List.of(validators);
			Assert.notEmpty(this.validators, "validators cannot be empty");
		}

		public static ResponseValidator withDefaults() {
			return new ResponseValidator(new InResponseToValidator(), new DestinationValidator(),
					new IssuerValidator());
		}

		@SafeVarargs
		public static ResponseValidator withDefaults(
				Converter<ResponseToken, Saml2ResponseValidatorResult>... validators) {
			List<Converter<ResponseToken, Saml2ResponseValidatorResult>> defaults = new ArrayList<>(DEFAULTS);
			defaults.addAll(List.of(validators));
			return new ResponseValidator(defaults.toArray(Converter[]::new));
		}

		@Override
		public Saml2ResponseValidatorResult convert(ResponseToken responseToken) {
			Response response = responseToken.getResponse();
			Collection<Saml2Error> errors = new ArrayList<>();
			List<String> statusCodes = BaseOpenSamlAuthenticationProvider.getStatusCodes(response);
			if (!BaseOpenSamlAuthenticationProvider.isSuccess(statusCodes)) {
				for (String statusCode : statusCodes) {
					String message = String.format("Invalid status [%s] for SAML response [%s]", statusCode,
							response.getID());
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, message));
				}
			}
			for (Converter<ResponseToken, Saml2ResponseValidatorResult> validator : this.validators) {
				errors.addAll(validator.convert(responseToken).getErrors());
			}
			if (response.getAssertions().isEmpty()) {
				errors.add(new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response."));
			}
			return Saml2ResponseValidatorResult.failure(errors);
		}

	}

	/**
	 * A default implementation of {@link OpenSaml5AuthenticationProvider}'s assertion
	 * validator. This does not check the signature as signature verification is performed
	 * by a different component
	 *
	 * @author Josh Cummings
	 * @since 6.5
	 */
	public static final class AssertionValidator implements Converter<AssertionToken, Saml2ResponseValidatorResult> {

		private final SAML20AssertionValidator assertionValidator;

		private Consumer<Map<String, Object>> paramsConsumer = (map) -> {
		};

		public AssertionValidator(SAML20AssertionValidator assertionValidator) {
			this.assertionValidator = assertionValidator;
		}

		@Override
		public Saml2ResponseValidatorResult convert(AssertionToken source) {
			Assertion assertion = source.getAssertion();
			ValidationContext validationContext = createValidationContext(source);
			try {
				ValidationResult result = this.assertionValidator.validate(assertion, validationContext);
				if (result == ValidationResult.VALID) {
					return Saml2ResponseValidatorResult.success();
				}
			}
			catch (Exception ex) {
				String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
						((Response) assertion.getParent()).getID(), ex.getMessage());
				return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ASSERTION, message));
			}
			String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
					((Response) assertion.getParent()).getID(), validationContext.getValidationFailureMessages());
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ASSERTION, message));
		}

		/**
		 * Validate this assertion
		 * @param token the assertion to validate
		 * @return the validation result
		 */
		public Saml2ResponseValidatorResult validate(AssertionToken token) {
			return convert(token);
		}

		/**
		 * Mutate the map of OpenSAML {@link ValidationContext} parameters using the given
		 * {@code paramsConsumer}
		 * @param paramsConsumer the context parameters mutator
		 */
		public void setValidationContextParameters(Consumer<Map<String, Object>> paramsConsumer) {
			this.paramsConsumer = paramsConsumer;
		}

		private ValidationContext createValidationContext(AssertionToken assertionToken) {
			Saml2AuthenticationToken token = assertionToken.getToken();
			RelyingPartyRegistration relyingPartyRegistration = token.getRelyingPartyRegistration();
			String audience = relyingPartyRegistration.getEntityId();
			String recipient = relyingPartyRegistration.getAssertionConsumerServiceLocation();
			String assertingPartyEntityId = relyingPartyRegistration.getAssertingPartyMetadata().getEntityId();
			Map<String, Object> params = new HashMap<>();
			Assertion assertion = assertionToken.getAssertion();
			if (assertionContainsInResponseTo(assertion)) {
				String requestId = getAuthnRequestId(token.getAuthenticationRequest());
				params.put(SAML2AssertionValidationParameters.SC_VALID_IN_RESPONSE_TO, requestId);
			}
			params.put(SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, Collections.singleton(audience));
			params.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton(recipient));
			params.put(SAML2AssertionValidationParameters.VALID_ISSUERS, Collections.singleton(assertingPartyEntityId));
			params.put(SAML2AssertionValidationParameters.SC_CHECK_ADDRESS, false);
			this.paramsConsumer.accept(params);
			return new ValidationContext(params);
		}

		private static boolean assertionContainsInResponseTo(Assertion assertion) {
			if (assertion.getSubject() == null) {
				return false;
			}
			for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
				SubjectConfirmationData confirmationData = confirmation.getSubjectConfirmationData();
				if (confirmationData == null) {
					continue;
				}
				if (StringUtils.hasText(confirmationData.getInResponseTo())) {
					return true;
				}
			}
			return false;
		}

		private static String getAuthnRequestId(AbstractSaml2AuthenticationRequest serialized) {
			return (serialized != null) ? serialized.getId() : null;
		}

		/**
		 * Create the default assertion validator
		 * @return the default assertion validator
		 */
		public static AssertionValidator withDefaults() {
			return new Builder().build();
		}

		/**
		 * Use a builder to configure aspects of the validator
		 * @return the {@link Builder} for configuration {@link AssertionValidator}
		 */
		public static Builder builder() {
			return new Builder();
		}

		public static final class Builder {

			private final List<ConditionValidator> conditions = new ArrayList<>();

			private final List<SubjectConfirmationValidator> subjects = new ArrayList<>();

			private final Map<String, Object> validationParameters = new HashMap<>();

			private Builder() {
				this.conditions.add(new AudienceRestrictionConditionValidator());
				this.conditions.add(new DelegationRestrictionConditionValidator());
				this.conditions.add(new ValidConditionValidator(OneTimeUse.DEFAULT_ELEMENT_NAME));
				this.conditions.add(new ProxyRestrictionConditionValidator());
				this.subjects.add(new BearerSubjectConfirmationValidator());
				this.validationParameters.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(5));
			}

			/**
			 * Use this clock skew for validating assertion timestamps. The default is 5
			 * minutes.
			 * @param duration the duration to use
			 * @return the {@link Builder} for further configuration
			 */
			public Builder clockSkew(Duration duration) {
				this.validationParameters.put(SAML2AssertionValidationParameters.CLOCK_SKEW, duration);
				return this;
			}

			/**
			 * Mutate the map of {@link ValidationContext} static parameters. By default,
			 * these include:
			 * <ul>
			 * <li>{@link SAML2AssertionValidationParameters#SC_VALID_IN_RESPONSE_TO}</li>>
			 * <li>{@link SAML2AssertionValidationParameters#COND_VALID_AUDIENCES}</li>>
			 * <li>{@link SAML2AssertionValidationParameters#SC_VALID_RECIPIENTS}</li>>
			 * <li>{@link SAML2AssertionValidationParameters#VALID_ISSUERS}</li>>
			 * <li>{@link SAML2AssertionValidationParameters#SC_CHECK_ADDRESS}</li>>
			 * <li>{@link SAML2AssertionValidationParameters#CLOCK_SKEW}</li>>
			 * </ul>
			 *
			 * Note that several of these are required by various validation steps, for
			 * example {@code COND_VALID_AUDIENCES} is needed by
			 * {@link BearerSubjectConfirmationValidator}. If you do not want these, the
			 * best way to remove them is to remove the {@link #conditionValidators} or
			 * {@link #subjectValidators} themselves
			 * @param parameters the mutator to change the set of parameters
			 * @return
			 */
			public Builder validationContextParameters(Consumer<Map<String, Object>> parameters) {
				parameters.accept(this.validationParameters);
				return this;
			}

			/**
			 * Mutate the list of {@link ConditionValidator}s. By default, these include:
			 * <ul>
			 * <li>{@link AudienceRestrictionConditionValidator}</li>
			 * <li>{@link DelegationRestrictionConditionValidator}</li>
			 * <li>{@link ProxyRestrictionConditionValidator}</li>
			 * </ul>
			 * Note that it also adds a validator that skips the {@code saml2:OneTimeUse}
			 * element since this validator does not have caching facilities. However, you
			 * can construct your own instance of
			 * {@link org.opensaml.saml.saml2.assertion.impl.OneTimeUseConditionValidator}
			 * and supply it here.
			 * @param conditions the mutator for changing the list of conditions to use
			 * @return the {@link Builder} for further configuration
			 */
			public Builder conditionValidators(Consumer<List<ConditionValidator>> conditions) {
				conditions.accept(this.conditions);
				return this;
			}

			/**
			 * Mutate the list of {@link ConditionValidator}s.
			 * <p>
			 * By default it only has {@link BearerSubjectConfirmationValidator} for which
			 * address validation is skipped.
			 *
			 * To turn address validation on, use
			 * {@link #validationContextParameters(Consumer)} to set the
			 * {@link SAML2AssertionValidationParameters#SC_CHECK_ADDRESS} value.
			 * @param subjects the mutator for changing the list of conditions to use
			 * @return the {@link Builder} for further configuration
			 */
			public Builder subjectValidators(Consumer<List<SubjectConfirmationValidator>> subjects) {
				subjects.accept(this.subjects);
				return this;
			}

			/**
			 * Build the {@link AssertionValidator}
			 * @return the {@link AssertionValidator}
			 */
			public AssertionValidator build() {
				AssertionValidator validator = new AssertionValidator(new ValidSignatureAssertionValidator(
						this.conditions, this.subjects, List.of(), null, null, null));
				validator.setValidationContextParameters((params) -> params.putAll(this.validationParameters));
				return validator;
			}

		}

		private static final class ValidConditionValidator implements ConditionValidator {

			private final QName name;

			private ValidConditionValidator(QName name) {
				this.name = name;
			}

			@Nonnull
			@Override
			public QName getServicedCondition() {
				return this.name;
			}

			@Nonnull
			@Override
			public ValidationResult validate(@Nonnull Condition condition, @Nonnull Assertion assertion,
					@Nonnull ValidationContext context) {
				return ValidationResult.VALID;
			}

		}

		private static final class ValidSignatureAssertionValidator extends SAML20AssertionValidator {

			private ValidSignatureAssertionValidator(@Nullable Collection<ConditionValidator> newConditionValidators,
					@Nullable Collection<SubjectConfirmationValidator> newConfirmationValidators,
					@Nullable Collection<StatementValidator> newStatementValidators,
					@Nullable org.opensaml.saml.saml2.assertion.AssertionValidator newAssertionValidator,
					@Nullable SignatureTrustEngine newTrustEngine,
					@Nullable SignaturePrevalidator newSignaturePrevalidator) {
				super(newConditionValidators, newConfirmationValidators, newStatementValidators, newAssertionValidator,
						newTrustEngine, newSignaturePrevalidator);
			}

			@Nonnull
			@Override
			protected ValidationResult validateSignature(@Nonnull Assertion token, @Nonnull ValidationContext context)
					throws AssertionValidationException {
				return ValidationResult.VALID;
			}

		}

	}

	/**
	 * A default implementation of {@link OpenSaml5AuthenticationProvider}'s response
	 * authentication converter. It will take the principal name from the
	 * {@link org.opensaml.saml.saml2.core.NameID} element. It will also extract the
	 * assertion attributes and session indexes. You can either configure the principal
	 * name converter and granted authorities converter in this class or you can
	 * post-process this class's result through delegation.
	 *
	 * @author Josh Cummings
	 * @since 6.5
	 */
	public static final class ResponseAuthenticationConverter implements Converter<ResponseToken, Saml2Authentication> {

		private Converter<Assertion, String> principalNameConverter = ResponseAuthenticationConverter::authenticatedPrincipal;

		private Converter<Assertion, Collection<GrantedAuthority>> grantedAuthoritiesConverter = ResponseAuthenticationConverter::grantedAuthorities;

		@Override
		public Saml2Authentication convert(ResponseToken responseToken) {
			Response response = responseToken.response;
			Saml2AuthenticationToken token = responseToken.token;
			Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
			String username = this.principalNameConverter.convert(assertion);
			Map<String, List<Object>> attributes = BaseOpenSamlAuthenticationProvider.getAssertionAttributes(assertion);
			List<String> sessionIndexes = BaseOpenSamlAuthenticationProvider.getSessionIndexes(assertion);
			DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(username, attributes,
					sessionIndexes);
			String registrationId = responseToken.token.getRelyingPartyRegistration().getRegistrationId();
			principal.setRelyingPartyRegistrationId(registrationId);
			return new Saml2Authentication(principal, token.getSaml2Response(),
					this.grantedAuthoritiesConverter.convert(assertion));
		}

		/**
		 * Use this strategy to extract the principal name from the {@link Assertion}. By
		 * default, this will retrieve it from the
		 * {@link org.opensaml.saml.saml2.core.Subject}'s
		 * {@link org.opensaml.saml.saml2.core.NameID} value.
		 *
		 * <p>
		 * Note that because of this, if there is no
		 * {@link org.opensaml.saml.saml2.core.NameID} present, then the default throws an
		 * exception.
		 * </p>
		 * @param principalNameConverter the conversion strategy to use
		 */
		public void setPrincipalNameConverter(Converter<Assertion, String> principalNameConverter) {
			Assert.notNull(principalNameConverter, "principalNameConverter cannot be null");
			this.principalNameConverter = principalNameConverter;
		}

		/**
		 * Use this strategy to grant authorities to a principal given the first
		 * {@link Assertion} in the response. By default, this will grant
		 * {@code ROLE_USER}.
		 * @param grantedAuthoritiesConverter the conversion strategy to use
		 */
		public void setGrantedAuthoritiesConverter(
				Converter<Assertion, Collection<GrantedAuthority>> grantedAuthoritiesConverter) {
			Assert.notNull(grantedAuthoritiesConverter, "grantedAuthoritiesConverter cannot be null");
			this.grantedAuthoritiesConverter = grantedAuthoritiesConverter;
		}

		private static String authenticatedPrincipal(Assertion assertion) {
			if (!BaseOpenSamlAuthenticationProvider.hasName(assertion)) {
				throw new Saml2AuthenticationException(
						Saml2Error.subjectNotFound("Assertion [" + assertion.getID() + "] is missing a subject"));
			}
			return assertion.getSubject().getNameID().getValue();
		}

		private static Collection<GrantedAuthority> grantedAuthorities(Assertion assertion) {
			return AuthorityUtils.createAuthorityList("ROLE_USER");
		}

	}

}
