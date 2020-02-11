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

import org.junit.Test;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.web.util.UriUtils;

import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.assertingPartyCredentials;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyCredentials;

public class OpenSamlImplementationTests {

	@Test
	public void getInstance() {
		OpenSamlImplementation.getInstance();
	}

	@Test
	public void signQueryParametersWhenDataSuppliedReturnsValidSignature() throws Exception {
		OpenSamlImplementation impl = OpenSamlImplementation.getInstance();
		List<Saml2X509Credential> signCredentials = relyingPartyCredentials();
		List<Saml2X509Credential> verifyCredentials = assertingPartyCredentials();
		String samlRequest = "saml-request-example";
		String encoded = Saml2Utils.samlEncode(samlRequest.getBytes(UTF_8));
		String relayState = "test relay state";
		Map<String, String> parameters = impl.signQueryParameters(signCredentials, encoded, relayState);

		String queryString = "SAMLRequest=" +
				UriUtils.encode(encoded, ISO_8859_1) +
				"&RelayState=" +
				UriUtils.encode(relayState, ISO_8859_1) +
				"&SigAlg=" +
				UriUtils.encode(ALGO_ID_SIGNATURE_RSA_SHA256, ISO_8859_1);


		byte[] signature = Saml2Utils.samlDecode(parameters.get("Signature"));
		boolean result = XMLSigningUtil.verifyWithURI(
				getOpenSamlCredential(verifyCredentials.get(1), "local-sp-entity-id", UsageType.SIGNING),
				ALGO_ID_SIGNATURE_RSA_SHA256,
				signature,
				queryString.getBytes(UTF_8)
		);
		assertThat(result).isTrue();
	}

	private Credential getOpenSamlCredential(Saml2X509Credential credential, String localSpEntityId, UsageType usageType) {
		BasicCredential cred = CredentialSupport.getSimpleCredential(
				credential.getCertificate(),
				credential.getPrivateKey()
		);
		cred.setEntityId(localSpEntityId);
		cred.setUsageType(usageType);
		return cred;
	}
}
