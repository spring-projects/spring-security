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
package org.springframework.security.saml2.credentials;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.util.Assert;

/**
 * Saml2X509Credential is meant to hold an X509 certificate, or an X509 certificate and a
 * private key. Per:
 * https://www.oasis-open.org/committees/download.php/8958/sstc-saml-implementation-guidelines-draft-01.pdf
 * Line: 584, Section 4.3 Credentials Used for both signing, signature verification and
 * encryption/decryption
 *
 * @since 5.2
 * @deprecated Use {@link org.springframework.security.saml2.core.Saml2X509Credential}
 * instead
 */
@Deprecated
public class Saml2X509Credential {

	/**
	 * @deprecated Use
	 * {@link org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType}
	 * instead
	 */
	@Deprecated
	public enum Saml2X509CredentialType {

		VERIFICATION, ENCRYPTION, SIGNING, DECRYPTION,

	}

	private final PrivateKey privateKey;

	private final X509Certificate certificate;

	private final Set<Saml2X509CredentialType> credentialTypes;

	/**
	 * Creates a Saml2X509Credentials representing Identity Provider credentials for
	 * verification, encryption or both.
	 * @param certificate an IDP X509Certificate, cannot be null
	 * @param types credential types, must be one of
	 * {@link Saml2X509CredentialType#VERIFICATION} or
	 * {@link Saml2X509CredentialType#ENCRYPTION} or both.
	 */
	public Saml2X509Credential(X509Certificate certificate, Saml2X509CredentialType... types) {
		this(null, false, certificate, types);
		validateUsages(types, Saml2X509CredentialType.VERIFICATION, Saml2X509CredentialType.ENCRYPTION);
	}

	/**
	 * Creates a Saml2X509Credentials representing Service Provider credentials for
	 * signing, decryption or both.
	 * @param privateKey a private key used for signing or decryption, cannot be null
	 * @param certificate an SP X509Certificate shared with identity providers, cannot be
	 * null
	 * @param types credential types, must be one of
	 * {@link Saml2X509CredentialType#SIGNING} or
	 * {@link Saml2X509CredentialType#DECRYPTION} or both.
	 */
	public Saml2X509Credential(PrivateKey privateKey, X509Certificate certificate, Saml2X509CredentialType... types) {
		this(privateKey, true, certificate, types);
		validateUsages(types, Saml2X509CredentialType.SIGNING, Saml2X509CredentialType.DECRYPTION);
	}

	public Saml2X509Credential(PrivateKey privateKey, X509Certificate certificate, Set<Saml2X509CredentialType> types) {
		Assert.notNull(certificate, "certificate cannot be null");
		Assert.notEmpty(types, "credentialTypes cannot be empty");
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.credentialTypes = types;
	}

	private Saml2X509Credential(PrivateKey privateKey, boolean keyRequired, X509Certificate certificate,
			Saml2X509CredentialType... types) {
		Assert.notNull(certificate, "certificate cannot be null");
		Assert.notEmpty(types, "credentials types cannot be empty");
		if (keyRequired) {
			Assert.notNull(privateKey, "privateKey cannot be null");
		}
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.credentialTypes = new LinkedHashSet<>(Arrays.asList(types));
	}

	/**
	 * Returns true if the credential has a private key and can be used for signing, the
	 * types will contain {@link Saml2X509CredentialType#SIGNING}.
	 * @return true if the credential is a {@link Saml2X509CredentialType#SIGNING} type
	 */
	public boolean isSigningCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.SIGNING);
	}

	/**
	 * Returns true if the credential has a private key and can be used for decryption,
	 * the types will contain {@link Saml2X509CredentialType#DECRYPTION}.
	 * @return true if the credential is a {@link Saml2X509CredentialType#DECRYPTION} type
	 */
	public boolean isDecryptionCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.DECRYPTION);
	}

	/**
	 * Returns true if the credential has a certificate and can be used for signature
	 * verification, the types will contain {@link Saml2X509CredentialType#VERIFICATION}.
	 * @return true if the credential is a {@link Saml2X509CredentialType#VERIFICATION}
	 * type
	 */
	public boolean isSignatureVerficationCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.VERIFICATION);
	}

	/**
	 * Returns true if the credential has a certificate and can be used for signature
	 * verification, the types will contain {@link Saml2X509CredentialType#VERIFICATION}.
	 * @return true if the credential is a {@link Saml2X509CredentialType#VERIFICATION}
	 * type
	 */
	public boolean isEncryptionCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.ENCRYPTION);
	}

	/**
	 * Returns the credential types for this credential.
	 * @return a set of credential types/usages that this credential can be used for
	 */
	protected Set<Saml2X509CredentialType> getCredentialTypes() {
		return this.credentialTypes;
	}

	/**
	 * Returns the private key, or null if this credential type doesn't require one.
	 * @return the private key, or null
	 * @see #Saml2X509Credential(PrivateKey, X509Certificate, Saml2X509CredentialType...)
	 */
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	/**
	 * Returns the X509 certificate for ths credential. Cannot be null
	 * @return the X509 certificate
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		Saml2X509Credential that = (Saml2X509Credential) o;
		return Objects.equals(this.privateKey, that.privateKey) && this.certificate.equals(that.certificate)
				&& this.credentialTypes.equals(that.credentialTypes);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.privateKey, this.certificate, this.credentialTypes);
	}

	private void validateUsages(Saml2X509CredentialType[] usages, Saml2X509CredentialType... validUsages) {
		for (Saml2X509CredentialType usage : usages) {
			boolean valid = false;
			for (Saml2X509CredentialType validUsage : validUsages) {
				if (usage == validUsage) {
					valid = true;
					break;
				}
			}
			Assert.state(valid, () -> usage + " is not a valid usage for this credential");
		}
	}

}
