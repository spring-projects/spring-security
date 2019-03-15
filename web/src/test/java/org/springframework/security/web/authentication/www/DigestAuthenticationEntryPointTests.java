/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.www;

import java.util.Map;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.util.StringUtils;


/**
 * Tests {@link DigestAuthenticationEntryPoint}.
 *
 * @author Ben Alex
 */
public class DigestAuthenticationEntryPointTests extends TestCase {
    //~ Methods ========================================================================================================

    private void checkNonceValid(String nonce) {
        // Check the nonce seems to be generated correctly
        // format of nonce is:
        //   base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
        assertTrue(Base64.isArrayByteBase64(nonce.getBytes()));

        String decodedNonce = new String(Base64.decodeBase64(nonce.getBytes()));
        String[] nonceTokens = StringUtils.delimitedListToStringArray(decodedNonce, ":");
        assertEquals(2, nonceTokens.length);

        String expectedNonceSignature = DigestUtils.md5Hex(nonceTokens[0] + ":" + "key");
        assertEquals(expectedNonceSignature, nonceTokens[1]);
    }

    public void testDetectsMissingKey() throws Exception {
        DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
        ep.setRealmName("realm");

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("key must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingRealmName() throws Exception {
        DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
        ep.setKey("dcdc");
        ep.setNonceValiditySeconds(12);

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("realmName must be specified", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
        assertEquals(300, ep.getNonceValiditySeconds()); // 5 mins default
        ep.setRealmName("realm");
        assertEquals("realm", ep.getRealmName());
        ep.setKey("dcdc");
        assertEquals("dcdc", ep.getKey());
        ep.setNonceValiditySeconds(12);
        assertEquals(12, ep.getNonceValiditySeconds());
    }

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
        assertEquals(401, response.getStatus());
        assertEquals(true, response.getHeader("WWW-Authenticate").toString().startsWith("Digest "));

        // Break up response header
        String header = response.getHeader("WWW-Authenticate").toString().substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map<String,String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");

        assertEquals("hello", headerMap.get("realm"));
        assertEquals("auth", headerMap.get("qop"));
        assertNull(headerMap.get("stale"));

        checkNonceValid((String) headerMap.get("nonce"));
    }

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
        assertEquals(401, response.getStatus());
        assertTrue(response.getHeader("WWW-Authenticate").toString().startsWith("Digest "));

        // Break up response header
        String header = response.getHeader("WWW-Authenticate").toString().substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map<String,String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");

        assertEquals("hello", headerMap.get("realm"));
        assertEquals("auth", headerMap.get("qop"));
        assertEquals("true", headerMap.get("stale"));

        checkNonceValid((String) headerMap.get("nonce"));
    }
}
