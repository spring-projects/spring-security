/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.www;

import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link DigestAuthenticationEntryPoint}.
 *
 * @author Ben Alex
 */
public class DigestAuthenticationEntryPointTests {

	private void checkNonceValid(String nonce) {
		// Check the nonce seems to be generated correctly
		// format of nonce is:
		// base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
		assertThat(Base64.isArrayByteBase64(nonce.getBytes())).isTrue();
		String decodedNonce = new String(Base64.decodeBase64(nonce.getBytes()));
		String[] nonceTokens = StringUtils.delimitedListToStringArray(decodedNonce, ":");
		assertThat(nonceTokens).hasSize(2);
		String expectedNonceSignature = DigestUtils.md5Hex(nonceTokens[0] + ":" + "key");
		assertThat(nonceTokens[1]).isEqualTo(expectedNonceSignature);
	}

	@Test
	public void testDetectsMissingKey() throws Exception {
		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		ep.setRealmName("realm");
		try {
			ep.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("key must be specified");
		}
	}

	@Test
	public void testDetectsMissingRealmName() throws Exception {
		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		ep.setKey("dcdc");
		ep.setNonceValiditySeconds(12);
		try {
			ep.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("realmName must be specified");
		}
	}

	@Test
	public void testGettersSetters() {
		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		assertThat(ep.getNonceValiditySeconds()).isEqualTo(300); // 5 mins default
		ep.setRealmName("realm");
		assertThat(ep.getRealmName()).isEqualTo("realm");
		ep.setKey("dcdc");
		assertThat(ep.getKey()).isEqualTo("dcdc");
		ep.setNonceValiditySeconds(12);
		assertThat(ep.getNonceValiditySeconds()).isEqualTo(12);
	}

	@Test
	public void testNormalOperation() throws Exception {
		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		ep.setRealmName("hello");
		ep.setKey("key");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.afterPropertiesSet();
		ep.commence(request, response, new DisabledException("foobar"));
		// Check response is properly formed
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate").toString()).startsWith("Digest ");
		// Break up response header
		String header = response.getHeader("WWW-Authenticate").toString().substring(7);
		String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
		Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");
		assertThat(headerMap.get("realm")).isEqualTo("hello");
		assertThat(headerMap.get("qop")).isEqualTo("auth");
		assertThat(headerMap.get("stale")).isNull();
		checkNonceValid(headerMap.get("nonce"));
	}

	@Test
	public void testOperationIfDueToStaleNonce() throws Exception {
		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		ep.setRealmName("hello");
		ep.setKey("key");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/some_path");
		MockHttpServletResponse response = new MockHttpServletResponse();
		ep.afterPropertiesSet();
		ep.commence(request, response, new NonceExpiredException("expired nonce"));
		// Check response is properly formed
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader("WWW-Authenticate").toString()).startsWith("Digest ");
		// Break up response header
		String header = response.getHeader("WWW-Authenticate").toString().substring(7);
		String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
		Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");
		assertThat(headerMap.get("realm")).isEqualTo("hello");
		assertThat(headerMap.get("qop")).isEqualTo("auth");
		assertThat(headerMap.get("stale")).isEqualTo("true");
		checkNonceValid(headerMap.get("nonce"));
	}

}
