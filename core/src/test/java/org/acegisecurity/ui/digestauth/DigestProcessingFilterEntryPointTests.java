/* Copyright 2004, 2005 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.ui.digestauth;

import junit.framework.TestCase;

import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.util.StringSplitUtils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import org.springframework.util.StringUtils;

import java.util.Map;


/**
 * Tests {@link DigestProcessingFilterEntryPoint}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DigestProcessingFilterEntryPointTests extends TestCase {
    //~ Constructors ===========================================================

    public DigestProcessingFilterEntryPointTests() {
        super();
    }

    public DigestProcessingFilterEntryPointTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(DigestProcessingFilterEntryPointTests.class);
    }

    public void testDetectsMissingKey() throws Exception {
        DigestProcessingFilterEntryPoint ep = new DigestProcessingFilterEntryPoint();
        ep.setRealmName("realm");

        try {
            ep.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("key must be specified", expected.getMessage());
        }
    }

    public void testDetectsMissingRealmName() throws Exception {
        DigestProcessingFilterEntryPoint ep = new DigestProcessingFilterEntryPoint();
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
        DigestProcessingFilterEntryPoint ep = new DigestProcessingFilterEntryPoint();
        assertEquals(300, ep.getNonceValiditySeconds()); // 5 mins default
        ep.setRealmName("realm");
        assertEquals("realm", ep.getRealmName());
        ep.setKey("dcdc");
        assertEquals("dcdc", ep.getKey());
        ep.setNonceValiditySeconds(12);
        assertEquals(12, ep.getNonceValiditySeconds());
    }

    public void testNormalOperation() throws Exception {
        DigestProcessingFilterEntryPoint ep = new DigestProcessingFilterEntryPoint();
        ep.setRealmName("hello");
        ep.setKey("key");

        MockHttpServletRequest request = new MockHttpServletRequest(
                "/some_path");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();

        ep.commence(request, response, new DisabledException("foobar"));

        // Check response is properly formed
        assertEquals(401, response.getError());
        assertTrue(response.getHeader("WWW-Authenticate").startsWith("Digest "));

        // Break up response header
        String header = response.getHeader("WWW-Authenticate").substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map headerMap = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries,
                "=", "\"");

        assertEquals("hello", headerMap.get("realm"));
        assertEquals("auth", headerMap.get("qop"));
        assertNull(headerMap.get("stale"));

        checkNonceValid((String) headerMap.get("nonce"));
    }

    public void testOperationIfDueToStaleNonce() throws Exception {
        DigestProcessingFilterEntryPoint ep = new DigestProcessingFilterEntryPoint();
        ep.setRealmName("hello");
        ep.setKey("key");

        MockHttpServletRequest request = new MockHttpServletRequest(
                "/some_path");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.afterPropertiesSet();

        ep.commence(request, response,
            new NonceExpiredException("expired nonce"));

        // Check response is properly formed
        assertEquals(401, response.getError());
        assertTrue(response.getHeader("WWW-Authenticate").startsWith("Digest "));

        // Break up response header
        String header = response.getHeader("WWW-Authenticate").substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map headerMap = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries,
                "=", "\"");

        assertEquals("hello", headerMap.get("realm"));
        assertEquals("auth", headerMap.get("qop"));
        assertEquals("true", headerMap.get("stale"));

        checkNonceValid((String) headerMap.get("nonce"));
    }

    private void checkNonceValid(String nonce) {
        // Check the nonce seems to be generated correctly
        // format of nonce is:  
        //   base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
        assertTrue(Base64.isArrayByteBase64(nonce.getBytes()));

        String decodedNonce = new String(Base64.decodeBase64(nonce.getBytes()));
        String[] nonceTokens = StringUtils.delimitedListToStringArray(decodedNonce,
                ":");
        assertEquals(2, nonceTokens.length);

        String expectedNonceSignature = DigestUtils.md5Hex(nonceTokens[0] + ":"
                + "key");
        assertEquals(expectedNonceSignature, nonceTokens[1]);
    }
}
