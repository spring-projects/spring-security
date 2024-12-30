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
import java.util.Map;
import java.util.function.Consumer;

import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.util.Assert;

/**
 * Implementation of {@link AuthenticationProvider} for SAML authentications when
 * receiving a {@code Response} object containing an {@code Assertion}. This
 * implementation uses the {@code OpenSAML 4} library.
 *
 * <p>
 * The {@link OpenSaml4AuthenticationProvider} supports {@link Saml2AuthenticationToken}
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
public final class OpenSaml4AuthenticationProvider implements AuthenticationProvider {

	private final BaseOpenSamlAuthenticationProvider delegate;

	/**
	 * Creates an {@link OpenSaml4AuthenticationProvider}
	 */
	public OpenSaml4AuthenticationProvider() {
		this.delegate = new BaseOpenSamlAuthenticationProvider(new OpenSaml4Template());
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
	 * OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
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
	 * You can still invoke the default validator by delgating to
	 * {@link #createAssertionValidator}, like so:
	 *
	 * <pre>
	 *	OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
	 *  provider.setAssertionValidator(assertionToken -&gt; {
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
	 *		createDefaultAssertionValidator(assertionToken -&gt; {
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
	 * Construct a default strategy for validating the SAML 2.0 Response
	 * @return the default response validator strategy
	 * @since 5.6
	 */
	public static Converter<ResponseToken, Saml2ResponseValidatorResult> createDefaultResponseValidator() {
		Converter<BaseOpenSamlAuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> delegate = BaseOpenSamlAuthenticationProvider
			.createDefaultResponseValidator();
		return (token) -> delegate
			.convert(new BaseOpenSamlAuthenticationProvider.ResponseToken(token.getResponse(), token.getToken()));
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @return the default assertion validator strategy
	 */
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator() {
		return createDefaultAssertionValidatorWithParameters(
				(params) -> params.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(5)));
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
		Converter<BaseOpenSamlAuthenticationProvider.AssertionToken, ValidationContext> contextDelegate = (
				token) -> contextConverter.convert(new AssertionToken(token.getAssertion(), token.getToken()));
		Converter<BaseOpenSamlAuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> delegate = BaseOpenSamlAuthenticationProvider
			.createDefaultAssertionValidator(contextDelegate);
		return (token) -> delegate
			.convert(new BaseOpenSamlAuthenticationProvider.AssertionToken(token.getAssertion(), token.getToken()));
	}

	/**
	 * Construct a default strategy for validating each SAML 2.0 Assertion and associated
	 * {@link Authentication} token
	 * @param validationContextParameters a consumer for editing the values passed to the
	 * {@link ValidationContext} for each assertion being validated
	 * @return the default assertion validator strategy
	 * @since 5.8
	 */
	public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidatorWithParameters(
			Consumer<Map<String, Object>> validationContextParameters) {
		Converter<BaseOpenSamlAuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> delegate = BaseOpenSamlAuthenticationProvider
			.createDefaultAssertionValidatorWithParameters(validationContextParameters);
		return (token) -> delegate
			.convert(new BaseOpenSamlAuthenticationProvider.AssertionToken(token.getAssertion(), token.getToken()));
	}

	/**
	 * Construct a default strategy for converting a SAML 2.0 Response and
	 * {@link Authentication} token into a {@link Saml2Authentication}
	 * @return the default response authentication converter strategy
	 */
	public static Converter<ResponseToken, Saml2Authentication> createDefaultResponseAuthenticationConverter() {
		Converter<BaseOpenSamlAuthenticationProvider.ResponseToken, Saml2Authentication> delegate = BaseOpenSamlAuthenticationProvider
			.createDefaultResponseAuthenticationConverter();
		return (token) -> delegate
			.convert(new BaseOpenSamlAuthenticationProvider.ResponseToken(token.getResponse(), token.getToken()));
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

}
