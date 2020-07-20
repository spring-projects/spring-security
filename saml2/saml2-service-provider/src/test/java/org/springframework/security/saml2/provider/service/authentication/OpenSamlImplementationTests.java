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

package org.springframework.security.saml2.provider.service.authentication;

import java.util.Arrays;
import java.util.Map;

import org.junit.Test;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;

import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.web.util.UriUtils;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.getSigningCredential;
import static org.springframework.security.saml2.core.TestSaml2X509Credentials.assertingPartySigningCredential;
import static org.springframework.security.saml2.core.TestSaml2X509Credentials.relyingPartyVerifyingCredential;

public class OpenSamlImplementationTests {

	@Test
	public void getInstance() {
		OpenSamlImplementation.getInstance();
	}

	@Test
	public void signQueryParametersWhenDataSuppliedReturnsValidSignature() throws Exception {
		OpenSamlImplementation impl = OpenSamlImplementation.getInstance();
		Saml2X509Credential signingCredential = assertingPartySigningCredential();
		Saml2X509Credential verifyingCredential = relyingPartyVerifyingCredential();
		String samlRequest = "saml-request-example";
		String encoded = Saml2Utils.samlEncode(samlRequest.getBytes(UTF_8));
		String relayState = "test relay state";
		Map<String, String> parameters = impl.signQueryParameters(Arrays.asList(signingCredential), encoded, relayState);

		String queryString = "SAMLRequest=" +
				UriUtils.encode(encoded, ISO_8859_1) +
				"&RelayState=" +
				UriUtils.encode(relayState, ISO_8859_1) +
				"&SigAlg=" +
				UriUtils.encode(ALGO_ID_SIGNATURE_RSA_SHA256, ISO_8859_1);


		byte[] signature = Saml2Utils.samlDecode(parameters.get("Signature"));
		boolean result = XMLSigningUtil.verifyWithURI(
				getSigningCredential(verifyingCredential, "local-sp-entity-id"),
				ALGO_ID_SIGNATURE_RSA_SHA256,
				signature,
				queryString.getBytes(UTF_8)
		);
		assertThat(result).isTrue();
	}
}
