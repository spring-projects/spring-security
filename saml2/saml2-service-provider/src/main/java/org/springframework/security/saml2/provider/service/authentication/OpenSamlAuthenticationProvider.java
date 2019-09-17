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
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
import static org.springframework.util.Assert.notNull;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
public final class OpenSamlAuthenticationProvider implements AuthenticationProvider {

	private static Log logger = LogFactory.getLog(OpenSamlAuthenticationProvider.class);

	private final OpenSamlImplementation saml = OpenSamlImplementation.getInstance();
	private Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor = (a -> singletonList(new SimpleGrantedAuthority("ROLE_USER")));
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
			String xml = token.getSaml2Response();
			Response samlResponse = getSaml2Response(xml);

			Assertion assertion = validateSaml2Response(token, token.getRecipientUri(), samlResponse);
			final String username = getUsername(token, assertion);
			if (username == null) {
				throw new UsernameNotFoundException("Assertion [" +
						assertion.getID() +
						"] is missing a user identifier");
			}
			return new Saml2Authentication(
					() -> username, token.getSaml2Response(),
					this.authoritiesMapper.mapAuthorities(getAssertionAuthorities(assertion))
			);
		}catch (Saml2Exception | IllegalArgumentException e) {
			throw new AuthenticationServiceException(e.getMessage(), e);
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

	private String getUsername(Saml2AuthenticationToken token, Assertion assertion) {
		final Subject subject = assertion.getSubject();
		if (subject == null) {
			return null;
		}
		if (subject.getNameID() != null) {
			return subject.getNameID().getValue();
		}
		if (subject.getEncryptedID() != null) {
			NameID nameId = decrypt(token, subject.getEncryptedID());
			return nameId.getValue();
		}
		return null;
	}

	private Assertion validateSaml2Response(Saml2AuthenticationToken token,
											String recipient,
											Response samlResponse) throws AuthenticationException {
		if (hasText(samlResponse.getDestination()) && !recipient.equals(samlResponse.getDestination())) {
			throw new Saml2Exception("Invalid SAML response destination: " + samlResponse.getDestination());
		}

		final String issuer = samlResponse.getIssuer().getValue();
		if (logger.isDebugEnabled()) {
			logger.debug("Processing SAML response from " + issuer);
		}
		if (token == null) {
			throw new Saml2Exception(format("SAML 2 Provider for %s was not found.", issuer));
		}
		boolean responseSigned = hasValidSignature(samlResponse, token);
		for (Assertion a : samlResponse.getAssertions()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Checking plain assertion validity " + a);
			}
			if (isValidAssertion(recipient, a, token, !responseSigned)) {
				if (logger.isDebugEnabled()) {
					logger.debug("Found valid assertion. Skipping potential others.");
				}
				return a;
			}
		}
		for (EncryptedAssertion ea : samlResponse.getEncryptedAssertions()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Checking encrypted assertion validity " + ea);
			}

			Assertion a = decrypt(token, ea);
			if (isValidAssertion(recipient, a, token, false)) {
				if (logger.isDebugEnabled()) {
					logger.debug("Found valid encrypted assertion. Skipping potential others.");
				}
				return a;
			}
		}
		throw new InsufficientAuthenticationException("Unable to find a valid assertion");
	}

	private boolean hasValidSignature(SignableSAMLObject samlResponse, Saml2AuthenticationToken token) {
		if (!samlResponse.isSigned()) {
			return false;
		}

		final List<X509Certificate> verificationKeys = getVerificationKeys(token);
		if (verificationKeys.isEmpty()) {
			return false;
		}

		for (X509Certificate key : verificationKeys) {
			final Credential credential = getVerificationCredential(key);
			try {
				SignatureValidator.validate(samlResponse.getSignature(), credential);
				return true;
			}
			catch (SignatureException ignored) {
				logger.debug("Signature validation failed", ignored);
			}
		}
		return false;
	}

	private boolean isValidAssertion(String recipient, Assertion a, Saml2AuthenticationToken token, boolean signatureRequired) {
		final SAML20AssertionValidator validator = getAssertionValidator(token);
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
			return false;
		}
		a.setSignature(null);

		// validation for recipient
		ValidationContext vctx = new ValidationContext(validationParams);
		try {
			final ValidationResult result = validator.validate(a, vctx);
			final boolean valid = result.equals(ValidationResult.VALID);
			if (!valid) {
				if (logger.isDebugEnabled()) {
					logger.debug(format("Failed to validate assertion from %s with user %s", token.getIdpEntityId(),
							getUsername(token, a)
					));
				}
			}
			return valid;
		}
		catch (AssertionValidationException e) {
			if (logger.isDebugEnabled()) {
				logger.debug("Failed to validate assertion:", e);
			}
			return false;
		}

	}

	private Response getSaml2Response(String xml) throws Saml2Exception, AuthenticationException {
		final Object result = this.saml.resolve(xml);
		if (result == null) {
			throw new AuthenticationCredentialsNotFoundException("SAMLResponse returned null object");
		}
		else if (result instanceof Response) {
			return (Response) result;
		}
		throw new IllegalArgumentException("Invalid response class:"+result.getClass().getName());
	}

	private SAML20AssertionValidator getAssertionValidator(Saml2AuthenticationToken provider) {
		List<ConditionValidator> conditions = Collections.singletonList(new AudienceRestrictionConditionValidator());
		final BearerSubjectConfirmationValidator subjectConfirmationValidator =
				new BearerSubjectConfirmationValidator();

		List<SubjectConfirmationValidator> subjects = Collections.singletonList(subjectConfirmationValidator);
		List<StatementValidator> statements = Collections.emptyList();

		Set<Credential> credentials = new HashSet<>();
		for (X509Certificate key : getVerificationKeys(provider)) {
			final Credential cred = getVerificationCredential(key);
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

	private Assertion decrypt(Saml2AuthenticationToken token, EncryptedAssertion assertion) {
		Saml2Exception last = null;
		List<Saml2X509Credential> decryptionCredentials = getDecryptionCredentials(token);
		if (decryptionCredentials.isEmpty()) {
			throw new Saml2Exception("No valid decryption credentials found.");
		}
		for (Saml2X509Credential key : decryptionCredentials) {
			final Decrypter decrypter = getDecrypter(key);
			try {
				return decrypter.decrypt(assertion);
			}
			catch (DecryptionException e) {
				last = new Saml2Exception(e);
			}
		}
		throw last;
	}

	private NameID decrypt(Saml2AuthenticationToken token, EncryptedID assertion) {
		Saml2Exception last = null;
		List<Saml2X509Credential> decryptionCredentials = getDecryptionCredentials(token);
		if (decryptionCredentials.isEmpty()) {
			throw new Saml2Exception("No valid decryption credentials found.");
		}
		for (Saml2X509Credential key : decryptionCredentials) {
			final Decrypter decrypter = getDecrypter(key);
			try {
				return (NameID) decrypter.decrypt(assertion);
			}
			catch (DecryptionException e) {
				last = new Saml2Exception(e);
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

	private List<X509Certificate> getVerificationKeys(Saml2AuthenticationToken token) {
		List<X509Certificate> result = new LinkedList<>();
		for (Saml2X509Credential c : token.getX509Credentials()) {
			if (c.isSignatureVerficationCredential()) {
				result.add(c.getCertificate());
			}
		}
		return result;
	}
}
