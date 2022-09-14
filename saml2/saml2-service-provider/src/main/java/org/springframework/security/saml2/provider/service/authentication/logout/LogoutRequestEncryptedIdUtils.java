/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Utility methods for decrypting EncryptedID from SAML logout request with OpenSAML
 *
 * For internal use only.
 *
 * this is mainly a adapted copy of OpenSamlDecryptionUtils
 *
 * @author Robert Stoiber
 */
final class LogoutRequestEncryptedIdUtils {

	private static final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			Arrays.asList(new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(),
					new SimpleRetrievalMethodEncryptedKeyResolver()));

	static SAMLObject decryptEncryptedId(EncryptedID encryptedId, RelyingPartyRegistration registration) {
		Decrypter decrypter = decrypter(registration);
		try {
			return decrypter.decrypt(encryptedId);

		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static Decrypter decrypter(RelyingPartyRegistration registration) {
		Collection<Credential> credentials = new ArrayList<>();
		for (Saml2X509Credential key : registration.getDecryptionX509Credentials()) {
			Credential cred = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
			credentials.add(cred);
		}
		KeyInfoCredentialResolver resolver = new CollectionKeyInfoCredentialResolver(credentials);
		Decrypter decrypter = new Decrypter(null, resolver, encryptedKeyResolver);
		decrypter.setRootInNewDocument(true);
		return decrypter;
	}

	private LogoutRequestEncryptedIdUtils() {
	}

}
