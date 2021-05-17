/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
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
 * Utility methods for decrypting SAML components with OpenSAML
 *
 * For internal use only.
 *
 * @author Josh Cummings
 */
final class OpenSamlDecryptionUtils {

	private static final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			Arrays.asList(new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(),
					new SimpleRetrievalMethodEncryptedKeyResolver()));

	static void decryptResponseElements(Response response, RelyingPartyRegistration registration) {
		Decrypter decrypter = decrypter(registration);
		for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
			try {
				Assertion assertion = decrypter.decrypt(encryptedAssertion);
				response.getAssertions().add(assertion);
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		}
	}

	static void decryptAssertionElements(Assertion assertion, RelyingPartyRegistration registration) {
		Decrypter decrypter = decrypter(registration);
		for (AttributeStatement statement : assertion.getAttributeStatements()) {
			for (EncryptedAttribute encryptedAttribute : statement.getEncryptedAttributes()) {
				try {
					Attribute attribute = decrypter.decrypt(encryptedAttribute);
					statement.getAttributes().add(attribute);
				}
				catch (Exception ex) {
					throw new Saml2Exception(ex);
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

	private OpenSamlDecryptionUtils() {
	}

}
