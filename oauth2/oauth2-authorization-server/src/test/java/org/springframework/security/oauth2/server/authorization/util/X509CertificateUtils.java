/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * @author Joe Grandja
 */
public final class X509CertificateUtils {

	private static final String BC_PROVIDER = "BC";

	private static final String SHA256_RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";

	private static final Date DEFAULT_START_DATE;

	private static final Date DEFAULT_END_DATE;

	static {
		Security.addProvider(new BouncyCastleProvider());

		// Setup default certificate start date to yesterday and end date for 1 year
		// validity
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.DATE, -1);
		DEFAULT_START_DATE = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		DEFAULT_END_DATE = calendar.getTime();
	}

	private X509CertificateUtils() {
	}

	public static KeyPair generateRSAKeyPair() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
			keyPairGenerator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	public static X509Certificate createTrustAnchorCertificate(KeyPair keyPair, String distinguishedName)
			throws Exception {
		X500Principal subject = new X500Principal(distinguishedName);
		BigInteger serialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, serialNum, DEFAULT_START_DATE,
				DEFAULT_END_DATE, subject, keyPair.getPublic());

		// Add Extensions
		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		certBuilder
			// A BasicConstraints to mark root certificate as CA certificate
			.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
			.addExtension(Extension.subjectKeyIdentifier, false,
					extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

		ContentSigner signer = new JcaContentSignerBuilder(SHA256_RSA_SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER)
			.build(keyPair.getPrivate());

		JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC_PROVIDER);

		return converter.getCertificate(certBuilder.build(signer));
	}

	public static X509Certificate createCACertificate(X509Certificate signerCert, PrivateKey signerKey,
			PublicKey certKey, String distinguishedName) throws Exception {

		X500Principal subject = new X500Principal(distinguishedName);
		BigInteger serialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(signerCert.getSubjectX500Principal(),
				serialNum, DEFAULT_START_DATE, DEFAULT_END_DATE, subject, certKey);

		// Add Extensions
		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		certBuilder
			// A BasicConstraints to mark as CA certificate and how many CA certificates
			// can follow it in the chain
			// (with 0 meaning the chain ends with the next certificate in the chain).
			.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
			// KeyUsage specifies what the public key in the certificate can be used for.
			// In this case, it can be used for signing other certificates and/or
			// signing Certificate Revocation Lists (CRLs).
			.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
			.addExtension(Extension.authorityKeyIdentifier, false,
					extensionUtils.createAuthorityKeyIdentifier(signerCert))
			.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(certKey));

		ContentSigner signer = new JcaContentSignerBuilder(SHA256_RSA_SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER)
			.build(signerKey);

		JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC_PROVIDER);

		return converter.getCertificate(certBuilder.build(signer));
	}

	public static X509Certificate createEndEntityCertificate(X509Certificate signerCert, PrivateKey signerKey,
			PublicKey certKey, String distinguishedName) throws Exception {

		X500Principal subject = new X500Principal(distinguishedName);
		BigInteger serialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(signerCert.getSubjectX500Principal(),
				serialNum, DEFAULT_START_DATE, DEFAULT_END_DATE, subject, certKey);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
			.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
			.addExtension(Extension.authorityKeyIdentifier, false,
					extensionUtils.createAuthorityKeyIdentifier(signerCert))
			.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(certKey));

		ContentSigner signer = new JcaContentSignerBuilder(SHA256_RSA_SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER)
			.build(signerKey);

		JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC_PROVIDER);

		return converter.getCertificate(certBuilder.build(signer));
	}

}
