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
package org.springframework.security.saml2.core;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.util.Assert;

import static java.util.Arrays.asList;
import static org.springframework.util.Assert.notEmpty;
import static org.springframework.util.Assert.notNull;
import static org.springframework.util.Assert.state;

/**
 * An object for holding a public certificate, any associated private key, and its
 * intended <a href=
 * "https://www.oasis-open.org/committees/download.php/8958/sstc-saml-implementation-guidelines-draft-01.pdf">
 * usages </a> (Line 584, Section 4.3 Credentials).
 *
 * @since 5.4
 * @author Filip Hanik
 * @author Josh Cummings
 */
public final class Saml2X509Credential {

	public enum Saml2X509CredentialType {

		VERIFICATION, ENCRYPTION, SIGNING, DECRYPTION,

	}

	private final PrivateKey privateKey;

	private final X509Certificate certificate;

	private final Set<Saml2X509CredentialType> credentialTypes;

	/**
	 * Creates a {@link Saml2X509Credential} using the provided parameters
	 * @param certificate the credential's public certificiate
	 * @param types the credential's intended usages, must be one of
	 * {@link Saml2X509CredentialType#VERIFICATION} or
	 * {@link Saml2X509CredentialType#ENCRYPTION} or both.
	 */
	public Saml2X509Credential(X509Certificate certificate, Saml2X509CredentialType... types) {
		this(null, false, certificate, types);
		validateUsages(types, Saml2X509CredentialType.VERIFICATION, Saml2X509CredentialType.ENCRYPTION);
	}

	/**
	 * Creates a {@link Saml2X509Credential} using the provided parameters
	 * @param privateKey the credential's private key
	 * @param certificate the credential's public certificate
	 * @param types the credential's intended usages, must be one of
	 * {@link Saml2X509CredentialType#SIGNING} or
	 * {@link Saml2X509CredentialType#DECRYPTION} or both.
	 */
	public Saml2X509Credential(PrivateKey privateKey, X509Certificate certificate, Saml2X509CredentialType... types) {
		this(privateKey, true, certificate, types);
		validateUsages(types, Saml2X509CredentialType.SIGNING, Saml2X509CredentialType.DECRYPTION);
	}

	/**
	 * Creates a {@link Saml2X509Credential} using the provided parameters
	 * @param privateKey the credential's private key
	 * @param certificate the credential's public certificate
	 * @param types the credential's intended usages
	 */
	public Saml2X509Credential(PrivateKey privateKey, X509Certificate certificate, Set<Saml2X509CredentialType> types) {
		Assert.notNull(certificate, "certificate cannot be null");
		Assert.notNull(types, "credentialTypes cannot be null");
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.credentialTypes = types;
	}

	/**
	 * Create a {@link Saml2X509Credential} that can be used for encryption.
	 * @param certificate the certificate to use for encryption
	 */
	public static Saml2X509Credential encryption(X509Certificate certificate) {
		return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION);
	}

	/**
	 * Create a {@link Saml2X509Credential} that can be used for verification.
	 * @param certificate the certificate to use for verification
	 */
	public static Saml2X509Credential verification(X509Certificate certificate) {
		return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
	}

	/**
	 * Create a {@link Saml2X509Credential} that can be used for decryption.
	 * @param privateKey the private key to use for decryption
	 * @param certificate the certificate to use for decryption
	 */
	public static Saml2X509Credential decryption(PrivateKey privateKey, X509Certificate certificate) {
		return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
	}

	/**
	 * Create a {@link Saml2X509Credential} that can be used for signing.
	 * @param privateKey the private key to use for signing
	 * @param certificate the certificate to use for signing
	 */
	public static Saml2X509Credential signing(PrivateKey privateKey, X509Certificate certificate) {
		return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
	}

	private Saml2X509Credential(PrivateKey privateKey, boolean keyRequired, X509Certificate certificate,
			Saml2X509CredentialType... types) {
		notNull(certificate, "certificate cannot be null");
		notEmpty(types, "credentials types cannot be empty");
		if (keyRequired) {
			notNull(privateKey, "privateKey cannot be null");
		}
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.credentialTypes = new LinkedHashSet<>(asList(types));
	}

	/**
	 * Get the private key for this credential
	 * @return the private key, may be null
	 * @see {@link #Saml2X509Credential(PrivateKey, X509Certificate, Saml2X509CredentialType...)}
	 */
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	/**
	 * Get the public certificate for this credential
	 * @return the public certificate
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

	/**
	 * Indicate whether this credential can be used for signing
	 * @return true if the credential has a {@link Saml2X509CredentialType#SIGNING} type
	 */
	public boolean isSigningCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.SIGNING);
	}

	/**
	 * Indicate whether this credential can be used for decryption
	 * @return true if the credential has a {@link Saml2X509CredentialType#DECRYPTION}
	 * type
	 */
	public boolean isDecryptionCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.DECRYPTION);
	}

	/**
	 * Indicate whether this credential can be used for verification
	 * @return true if the credential has a {@link Saml2X509CredentialType#VERIFICATION}
	 * type
	 */
	public boolean isVerificationCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.VERIFICATION);
	}

	/**
	 * Indicate whether this credential can be used for encryption
	 * @return true if the credential has a {@link Saml2X509CredentialType#ENCRYPTION}
	 * type
	 */
	public boolean isEncryptionCredential() {
		return getCredentialTypes().contains(Saml2X509CredentialType.ENCRYPTION);
	}

	/**
	 * List all this credential's intended usages
	 * @return the set of this credential's intended usages
	 */
	public Set<Saml2X509CredentialType> getCredentialTypes() {
		return this.credentialTypes;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
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
			state(valid, () -> usage + " is not a valid usage for this credential");
		}
	}

}
