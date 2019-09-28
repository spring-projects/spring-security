/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.common.SignableSAMLObject;
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
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.lang.String.format;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.DECRYPTION_ERROR;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INVALID_DESTINATION;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.INVALID_ISSUER;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.MALFORMED_RESPONSE_DATA;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.SUBJECT_NOT_FOUND;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.UNKNOWN_RESPONSE_CLASS;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.USERNAME_NOT_FOUND;
import static org.springframework.util.Assert.notNull;
import static org.springframework.util.StringUtils.hasText;

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
			Response samlResponse = getSaml2Response(token);
			Assertion assertion = validateSaml2Response(token, token.getRecipientUri(), samlResponse);
			String username = getUsername(token, assertion);
			return new Saml2Authentication(
					() -> username, token.getSaml2Response(),
					this.authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion))
			);
		} catch (Saml2AuthenticationException e) {
			throw e;
		} catch (Exception e) {
			throw authException(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, e.getMessage(), e);
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

	private String getUsername(Saml2AuthenticationToken token, Assertion assertion) throws Saml2AuthenticationException {
		String username = null;
		Subject subject = assertion.getSubject();
		if (subject == null) {
			throw authException(SUBJECT_NOT_FOUND, "Assertion [" + assertion.getID() + "] is missing a subject");
		}
		if (subject.getNameID() != null) {
			username = subject.getNameID().getValue();
		}
		else if (subject.getEncryptedID() != null) {
			NameID nameId = decrypt(token, subject.getEncryptedID());
			username = nameId.getValue();
		}
		if (username == null) {
			throw authException(USERNAME_NOT_FOUND, "Assertion [" + assertion.getID() + "] is missing a user identifier");
		}
		return username;
	}

	private Assertion validateSaml2Response(Saml2AuthenticationToken token,
											String recipient,
											Response samlResponse) throws Saml2AuthenticationException {
		//optional validation if the response contains a destination
		if (hasText(samlResponse.getDestination()) && !recipient.equals(samlResponse.getDestination())) {
			throw authException(INVALID_DESTINATION, "Invalid SAML response destination: " + samlResponse.getDestination());
		}

		String issuer = samlResponse.getIssuer().getValue();
		if (logger.isDebugEnabled()) {
			logger.debug("Validating SAML response from " + issuer);
		}
		if (!hasText(issuer) || (!issuer.equals(token.getIdpEntityId()))) {
			String message = String.format("Response issuer '%s' doesn't match '%s'", issuer, token.getIdpEntityId());
			throw authException(INVALID_ISSUER, message);
		}
		Saml2AuthenticationException lastValidationError = null;

		boolean responseSigned = hasValidSignature(samlResponse, token);
		for (Assertion a : samlResponse.getAssertions()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Checking plain assertion validity " + a);
			}
			try {
				validateAssertion(recipient, a, token, !responseSigned);
				return a;
			} catch (Saml2AuthenticationException e) {
				lastValidationError = e;
			}
		}
		for (EncryptedAssertion ea : samlResponse.getEncryptedAssertions()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Checking encrypted assertion validity " + ea);
			}
			try {
				Assertion a = decrypt(token, ea);
				validateAssertion(recipient, a, token, !responseSigned);
				return a;
			} catch (Saml2AuthenticationException e) {
				lastValidationError = e;
			}
		}
		if (lastValidationError != null) {
			throw lastValidationError;
		}
		else {
			throw authException(MALFORMED_RESPONSE_DATA, "No assertions found in response.");
		}
	}

	private boolean hasValidSignature(SignableSAMLObject samlObject, Saml2AuthenticationToken token) {
		if (!samlObject.isSigned()) {
			if (logger.isDebugEnabled()) {
				logger.debug("SAML object is not signed, no signatures found");
			}
			return false;
		}

		List<X509Certificate> verificationKeys = getVerificationCertificates(token);
		if (verificationKeys.isEmpty()) {
			return false;
		}

		for (X509Certificate certificate : verificationKeys) {
			Credential credential = getVerificationCredential(certificate);
			try {
				SignatureValidator.validate(samlObject.getSignature(), credential);
				if (logger.isDebugEnabled()) {
					logger.debug("Valid signature found in SAML object:"+samlObject.getClass().getName());
				}
				return true;
			}
			catch (SignatureException ignored) {
				if (logger.isTraceEnabled()) {
					logger.trace("Signature validation failed with cert:"+certificate.toString(), ignored);
				}
				else if (logger.isDebugEnabled()) {
					logger.debug("Signature validation failed with cert:"+certificate.toString());
				}
			}
		}
		return false;
	}

	private void validateAssertion(String recipient, Assertion a, Saml2AuthenticationToken token, boolean signatureRequired) {
		SAML20AssertionValidator validator = getAssertionValidator(token);
		Map<String, Object> validationParams = new HashMap<>();
		validationParams.put(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false);
		validationParams.put(
				SAML2AssertionValidationParameters.CLOCK_SKEW,
				this.responseTimeValidationSkew.toMillis()
		);
		validationParams.put(
				SAML2AssertionValidationParameters.COND_VALID_AUDIENCES,
				singleton(token.getLocalSpEntityId())
		);
		if (hasText(recipient)) {
			validationParams.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, singleton(recipient));
		}

		if (signatureRequired && !hasValidSignature(a, token)) {
			if (logger.isDebugEnabled()) {
				logger.debug(format("Assertion [%s] does not a valid signature.", a.getID()));
			}
			throw authException(Saml2ErrorCodes.INVALID_SIGNATURE, "Assertion doesn't have a valid signature.");
		}
		//ensure that OpenSAML doesn't attempt signature validation, already performed
		a.setSignature(null);

		//remainder of assertion validation
		ValidationContext vctx = new ValidationContext(validationParams);
		try {
			ValidationResult result = validator.validate(a, vctx);
			boolean valid = result.equals(ValidationResult.VALID);
			if (!valid) {
				if (logger.isDebugEnabled()) {
					logger.debug(format("Failed to validate assertion from %s", token.getIdpEntityId()));
				}
				throw authException(Saml2ErrorCodes.INVALID_ASSERTION, vctx.getValidationFailureMessage());
			}
		}
		catch (AssertionValidationException e) {
			if (logger.isDebugEnabled()) {
				logger.debug("Failed to validate assertion:", e);
			}
			throw authException(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, e.getMessage(), e);
		}

	}

	private Response getSaml2Response(Saml2AuthenticationToken token) throws Saml2Exception, Saml2AuthenticationException {
		try {
			Object result = this.saml.resolve(token.getSaml2Response());
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

	private Saml2Error validationError(String code, String description) {
		return new Saml2Error(
				code,
				description
		);
	}

	private Saml2AuthenticationException authException(String code, String description) throws Saml2AuthenticationException {
		return new Saml2AuthenticationException(
				validationError(code, description)
		);
	}


	private Saml2AuthenticationException authException(String code, String description, Exception cause) throws Saml2AuthenticationException {
		return new Saml2AuthenticationException(
				validationError(code, description),
				cause
		);
	}

	private SAML20AssertionValidator getAssertionValidator(Saml2AuthenticationToken provider) {
		List<ConditionValidator> conditions = Collections.singletonList(new AudienceRestrictionConditionValidator());
		BearerSubjectConfirmationValidator subjectConfirmationValidator = new BearerSubjectConfirmationValidator();

		List<SubjectConfirmationValidator> subjects = Collections.singletonList(subjectConfirmationValidator);
		List<StatementValidator> statements = Collections.emptyList();

		Set<Credential> credentials = new HashSet<>();
		for (X509Certificate key : getVerificationCertificates(provider)) {
			Credential cred = getVerificationCredential(key);
			credentials.add(cred);
		}
		CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
		SignatureTrustEngine signatureTrustEngine = new ExplicitKeySignatureTrustEngine(
				credentialsResolver,
				DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
		);
		SignaturePrevalidator signaturePrevalidator = new SAMLSignatureProfileValidator();
		return new SAML20AssertionValidator(
				conditions,
				subjects,
				statements,
				signatureTrustEngine,
				signaturePrevalidator
		);
	}

	private Credential getVerificationCredential(X509Certificate certificate) {
		return CredentialSupport.getSimpleCredential(certificate, null);
	}

	private Decrypter getDecrypter(Saml2X509Credential key) {
		Credential credential = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
		KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
		Decrypter decrypter = new Decrypter(null, resolver, this.saml.getEncryptedKeyResolver());
		decrypter.setRootInNewDocument(true);
		return decrypter;
	}

	private Assertion decrypt(Saml2AuthenticationToken token, EncryptedAssertion assertion)
			throws Saml2AuthenticationException {
		Saml2AuthenticationException last = null;
		List<Saml2X509Credential> decryptionCredentials = getDecryptionCredentials(token);
		if (decryptionCredentials.isEmpty()) {
			throw authException(DECRYPTION_ERROR, "No valid decryption credentials found.");
		}
		for (Saml2X509Credential key : decryptionCredentials) {
			Decrypter decrypter = getDecrypter(key);
			try {
				return decrypter.decrypt(assertion);
			}
			catch (DecryptionException e) {
				last = authException(DECRYPTION_ERROR, e.getMessage(), e);
			}
		}
		throw last;
	}

	private NameID decrypt(Saml2AuthenticationToken token, EncryptedID assertion) throws Saml2AuthenticationException {
		Saml2AuthenticationException last = null;
		List<Saml2X509Credential> decryptionCredentials = getDecryptionCredentials(token);
		if (decryptionCredentials.isEmpty()) {
			throw authException(DECRYPTION_ERROR, "No valid decryption credentials found.");
		}
		for (Saml2X509Credential key : decryptionCredentials) {
			Decrypter decrypter = getDecrypter(key);
			try {
				return (NameID) decrypter.decrypt(assertion);
			}
			catch (DecryptionException e) {
				last = authException(DECRYPTION_ERROR, e.getMessage(), e);
			}
		}
		throw last;
	}

	private List<Saml2X509Credential> getDecryptionCredentials(Saml2AuthenticationToken token) {
		List<Saml2X509Credential> result = new LinkedList<>();
		for (Saml2X509Credential c : token.getX509Credentials()) {
			if (c.isDecryptionCredential()) {
				result.add(c);
			}
		}
		return result;
	}

	private List<X509Certificate> getVerificationCertificates(Saml2AuthenticationToken token) {
		List<X509Certificate> result = new LinkedList<>();
		for (Saml2X509Credential c : token.getX509Credentials()) {
			if (c.isSignatureVerficationCredential()) {
				result.add(c.getCertificate());
			}
		}
		return result;
	}
}
