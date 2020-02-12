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

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class Saml2UtilsTests {

	private static Base64 UNCHUNKED_ENCODER = new Base64(0, new byte[]{'\n'});
	private static final Base64 CHUNKED_ENCODER = new Base64(76, new byte[] { '\n' });

	@Test
	public void decodeWhenUsingApacheCommonsBase64ThenXmlIsValid() throws Exception {
		String responseUrlDecoded = getSsoCircleEncodedXml();
		String xml = new String(UNCHUNKED_ENCODER.decode(responseUrlDecoded.getBytes(UTF_8)), UTF_8);
		validateSsoCircleXml(xml);
	}

	@Test
	public void decodeWhenUsingApacheCommonsBase64ChunkedThenXmlIsValid() throws Exception {
		String responseUrlDecoded = getSsoCircleEncodedXml();
		String xml = new String(CHUNKED_ENCODER.decode(responseUrlDecoded.getBytes(UTF_8)), UTF_8);
		validateSsoCircleXml(xml);
	}

	@Test
	public void decodeWhenUsingSamlUtilsBase64ThenXmlIsValid() throws Exception {
		String responseUrlDecoded = getSsoCircleEncodedXml();
		String xml = new String(Saml2Utils.decode(responseUrlDecoded), UTF_8);
		validateSsoCircleXml(xml);
	}

	private void validateSsoCircleXml(String xml) {
		assertThat(xml)
				.contains("InResponseTo=\"ARQ9a73ead-7dcf-45a8-89eb-26f3c9900c36\"")
				.contains(" ID=\"s246d157446618e90e43fb79bdd4d9e9e19cf2c7c4\"")
				.contains("<saml:Issuer>https://idp.ssocircle.com</saml:Issuer>");
	}

	private String getSsoCircleEncodedXml() throws IOException {
		ClassPathResource resource = new ClassPathResource("saml2-response-sso-circle.encoded");
		String response = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
		return UriUtils.decode(response, UTF_8);
	}

}
