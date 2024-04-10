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

package org.springframework.security.oauth2.jose;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * @author Joe Grandja
 * @since 6.3
 */
public final class TestX509Certificates {

	public static final X509Certificate[] DEFAULT_PKI_CERTIFICATE;
	static {
		try {
			// Generate the Root certificate (Trust Anchor or most-trusted CA)
			KeyPair rootKeyPair = X509CertificateUtils.generateRSAKeyPair();
			String distinguishedName = "CN=spring-samples-trusted-ca, OU=Spring Samples, O=Spring, C=US";
			X509Certificate rootCertificate = X509CertificateUtils.createTrustAnchorCertificate(rootKeyPair,
					distinguishedName);

			// Generate the CA (intermediary) certificate
			KeyPair caKeyPair = X509CertificateUtils.generateRSAKeyPair();
			distinguishedName = "CN=spring-samples-ca, OU=Spring Samples, O=Spring, C=US";
			X509Certificate caCertificate = X509CertificateUtils.createCACertificate(rootCertificate,
					rootKeyPair.getPrivate(), caKeyPair.getPublic(), distinguishedName);

			// Generate certificate for subject1
			KeyPair subject1KeyPair = X509CertificateUtils.generateRSAKeyPair();
			distinguishedName = "CN=subject1, OU=Spring Samples, O=Spring, C=US";
			X509Certificate subject1Certificate = X509CertificateUtils.createEndEntityCertificate(caCertificate,
					caKeyPair.getPrivate(), subject1KeyPair.getPublic(), distinguishedName);

			DEFAULT_PKI_CERTIFICATE = new X509Certificate[] { subject1Certificate, caCertificate, rootCertificate };
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	public static final X509Certificate[] DEFAULT_SELF_SIGNED_CERTIFICATE;
	static {
		try {
			// Generate self-signed certificate for subject1
			KeyPair keyPair = X509CertificateUtils.generateRSAKeyPair();
			String distinguishedName = "CN=subject1, OU=Spring Samples, O=Spring, C=US";
			X509Certificate subject1SelfSignedCertificate = X509CertificateUtils.createTrustAnchorCertificate(keyPair,
					distinguishedName);

			DEFAULT_SELF_SIGNED_CERTIFICATE = new X509Certificate[] { subject1SelfSignedCertificate };
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	private TestX509Certificates() {
	}

}
