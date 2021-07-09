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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

public class Saml2X509CredentialTests {

	private PrivateKey key;

	private X509Certificate certificate;

	@BeforeEach
	public void setup() throws Exception {
		String keyData = "-----BEGIN PRIVATE KEY-----\n"
				+ "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANG7v8QjQGU3MwQE\n"
				+ "VUBxvH6Uuiy/MhZT7TV0ZNjyAF2ExA1gpn3aUxx6jYK5UnrpxRRE/KbeLucYbOhK\n"
				+ "cDECt77Rggz5TStrOta0BQTvfluRyoQtmQ5Nkt6Vqg7O2ZapFt7k64Sal7AftzH6\n"
				+ "Q2BxWN1y04bLdDrH4jipqRj/2qEFAgMBAAECgYEAj4ExY1jjdN3iEDuOwXuRB+Nn\n"
				+ "x7pC4TgntE2huzdKvLJdGvIouTArce8A6JM5NlTBvm69mMepvAHgcsiMH1zGr5J5\n"
				+ "wJz23mGOyhM1veON41/DJTVG+cxq4soUZhdYy3bpOuXGMAaJ8QLMbQQoivllNihd\n"
				+ "vwH0rNSK8LTYWWPZYIECQQDxct+TFX1VsQ1eo41K0T4fu2rWUaxlvjUGhK6HxTmY\n"
				+ "8OMJptunGRJL1CUjIb45Uz7SP8TPz5FwhXWsLfS182kRAkEA3l+Qd9C9gdpUh1uX\n"
				+ "oPSNIxn5hFUrSTW1EwP9QH9vhwb5Vr8Jrd5ei678WYDLjUcx648RjkjhU9jSMzIx\n"
				+ "EGvYtQJBAMm/i9NR7IVyyNIgZUpz5q4LI21rl1r4gUQuD8vA36zM81i4ROeuCly0\n"
				+ "KkfdxR4PUfnKcQCX11YnHjk9uTFj75ECQEFY/gBnxDjzqyF35hAzrYIiMPQVfznt\n"
				+ "YX/sDTE2AdVBVGaMj1Cb51bPHnNC6Q5kXKQnj/YrLqRQND09Q7ParX0CQQC5NxZr\n"
				+ "9jKqhHj8yQD6PlXTsY4Occ7DH6/IoDenfdEVD5qlet0zmd50HatN2Jiqm5ubN7CM\n" + "INrtuLp4YHbgk1mi\n"
				+ "-----END PRIVATE KEY-----";
		this.key = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(keyData.getBytes(StandardCharsets.UTF_8)));
		final CertificateFactory factory = CertificateFactory.getInstance("X.509");
		String certificateData = "-----BEGIN CERTIFICATE-----\n"
				+ "MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n"
				+ "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n"
				+ "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n"
				+ "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n"
				+ "MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n"
				+ "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n"
				+ "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n"
				+ "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n"
				+ "vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n"
				+ "+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n"
				+ "y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n"
				+ "XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n"
				+ "qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n"
				+ "RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n" + "-----END CERTIFICATE-----";
		this.certificate = (X509Certificate) factory
				.generateCertificate(new ByteArrayInputStream(certificateData.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void constructorWhenRelyingPartyWithCredentialsThenItSucceeds() {
		new Saml2X509Credential(this.key, this.certificate, Saml2X509CredentialType.SIGNING);
		new Saml2X509Credential(this.key, this.certificate, Saml2X509CredentialType.SIGNING,
				Saml2X509CredentialType.DECRYPTION);
		new Saml2X509Credential(this.key, this.certificate, Saml2X509CredentialType.DECRYPTION);
		Saml2X509Credential.signing(this.key, this.certificate);
		Saml2X509Credential.decryption(this.key, this.certificate);
	}

	@Test
	public void constructorWhenAssertingPartyWithCredentialsThenItSucceeds() {
		new Saml2X509Credential(this.certificate, Saml2X509CredentialType.VERIFICATION);
		new Saml2X509Credential(this.certificate, Saml2X509CredentialType.VERIFICATION,
				Saml2X509CredentialType.ENCRYPTION);
		new Saml2X509Credential(this.certificate, Saml2X509CredentialType.ENCRYPTION);
		Saml2X509Credential.verification(this.certificate);
		Saml2X509Credential.encryption(this.certificate);
	}

	@Test
	public void constructorWhenRelyingPartyWithoutCredentialsThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new Saml2X509Credential(null, (X509Certificate) null, Saml2X509CredentialType.SIGNING));
	}

	@Test
	public void constructorWhenRelyingPartyWithoutPrivateKeyThenItFails() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new Saml2X509Credential(null, this.certificate, Saml2X509CredentialType.SIGNING));
	}

	@Test
	public void constructorWhenRelyingPartyWithoutCertificateThenItFails() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new Saml2X509Credential(this.key, null, Saml2X509CredentialType.SIGNING));
	}

	@Test
	public void constructorWhenAssertingPartyWithoutCertificateThenItFails() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new Saml2X509Credential(null, Saml2X509CredentialType.SIGNING));
	}

	@Test
	public void constructorWhenRelyingPartyWithEncryptionUsageThenItFails() {
		assertThatIllegalStateException().isThrownBy(
				() -> new Saml2X509Credential(this.key, this.certificate, Saml2X509CredentialType.ENCRYPTION));
	}

	@Test
	public void constructorWhenRelyingPartyWithVerificationUsageThenItFails() {
		assertThatIllegalStateException().isThrownBy(
				() -> new Saml2X509Credential(this.key, this.certificate, Saml2X509CredentialType.VERIFICATION));
	}

	@Test
	public void constructorWhenAssertingPartyWithSigningUsageThenItFails() {
		assertThatIllegalStateException()
				.isThrownBy(() -> new Saml2X509Credential(this.certificate, Saml2X509CredentialType.SIGNING));
	}

	@Test
	public void constructorWhenAssertingPartyWithDecryptionUsageThenItFails() {
		assertThatIllegalStateException()
				.isThrownBy(() -> new Saml2X509Credential(this.certificate, Saml2X509CredentialType.DECRYPTION));
	}

	@Test
	public void factoryWhenRelyingPartyForSigningWithoutCredentialsThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.signing(null, null));
	}

	@Test
	public void factoryWhenRelyingPartyForSigningWithoutPrivateKeyThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.signing(null, this.certificate));
	}

	@Test
	public void factoryWhenRelyingPartyForSigningWithoutCertificateThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.signing(this.key, null));
	}

	@Test
	public void factoryWhenRelyingPartyForDecryptionWithoutCredentialsThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.decryption(null, null));
	}

	@Test
	public void factoryWhenRelyingPartyForDecryptionWithoutPrivateKeyThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.decryption(null, this.certificate));
	}

	@Test
	public void factoryWhenRelyingPartyForDecryptionWithoutCertificateThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.decryption(this.key, null));
	}

	@Test
	public void factoryWhenAssertingPartyForVerificationWithoutCertificateThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.verification(null));
	}

	@Test
	public void factoryWhenAssertingPartyForEncryptionWithoutCertificateThenItFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> Saml2X509Credential.encryption(null));
	}

}
