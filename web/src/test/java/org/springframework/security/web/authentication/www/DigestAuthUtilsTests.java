/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.www;

import junit.framework.TestCase;

import org.springframework.util.StringUtils;

import java.util.Map;


/**
 * Tests {@link org.springframework.security.util.StringSplitUtils}.
 *
 * @author Ben Alex
 */
public class DigestAuthUtilsTests extends TestCase {
    //~ Constructors ===================================================================================================

    //~ Methods ========================================================================================================

    public void testSplitEachArrayElementAndCreateMapNormalOperation() {
        // note it ignores malformed entries (ie those without an equals sign)
        String unsplit = "username=\"rod\", invalidEntryThatHasNoEqualsSign, realm=\"Contacts Realm\", nonce=\"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==\", uri=\"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4\", response=\"38644211cf9ac3da63ab639807e2baff\", qop=auth, nc=00000004, cnonce=\"2b8d329a8571b99a\"";
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(unsplit);
        Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");

        assertEquals("rod", headerMap.get("username"));
        assertEquals("Contacts Realm", headerMap.get("realm"));
        assertEquals("MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==", headerMap.get("nonce"));
        assertEquals("/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4",
                headerMap.get("uri"));
        assertEquals("38644211cf9ac3da63ab639807e2baff", headerMap.get("response"));
        assertEquals("auth", headerMap.get("qop"));
        assertEquals("00000004", headerMap.get("nc"));
        assertEquals("2b8d329a8571b99a", headerMap.get("cnonce"));
        assertEquals(8, headerMap.size());
    }

    public void testSplitEachArrayElementAndCreateMapRespectsInstructionNotToRemoveCharacters() {
        String unsplit = "username=\"rod\", realm=\"Contacts Realm\", nonce=\"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==\", uri=\"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4\", response=\"38644211cf9ac3da63ab639807e2baff\", qop=auth, nc=00000004, cnonce=\"2b8d329a8571b99a\"";
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(unsplit);
        Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", null);

        assertEquals("\"rod\"", headerMap.get("username"));
        assertEquals("\"Contacts Realm\"", headerMap.get("realm"));
        assertEquals("\"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==\"", headerMap.get("nonce"));
        assertEquals("\"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4\"",
                headerMap.get("uri"));
        assertEquals("\"38644211cf9ac3da63ab639807e2baff\"", headerMap.get("response"));
        assertEquals("auth", headerMap.get("qop"));
        assertEquals("00000004", headerMap.get("nc"));
        assertEquals("\"2b8d329a8571b99a\"", headerMap.get("cnonce"));
        assertEquals(8, headerMap.size());
    }

    public void testSplitEachArrayElementAndCreateMapReturnsNullIfArrayEmptyOrNull() {
        assertNull(DigestAuthUtils.splitEachArrayElementAndCreateMap(null, "=", "\""));
        assertNull(DigestAuthUtils.splitEachArrayElementAndCreateMap(new String[]{}, "=", "\""));
    }

    public void testSplitNormalOperation() {
        String unsplit = "username=\"rod==\"";
        assertEquals("username", DigestAuthUtils.split(unsplit, "=")[0]);
        assertEquals("\"rod==\"", DigestAuthUtils.split(unsplit, "=")[1]); // should not remove quotes or extra equals
    }

    public void testSplitRejectsNullsAndIncorrectLengthStrings() {
        try {
            DigestAuthUtils.split(null, "="); // null
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            DigestAuthUtils.split("", "="); // empty string
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            DigestAuthUtils.split("sdch=dfgf", null); // null
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            DigestAuthUtils.split("fvfv=dcdc", ""); // empty string
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            DigestAuthUtils.split("dfdc=dcdc", "BIGGER_THAN_ONE_CHARACTER");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSplitWorksWithDifferentDelimiters() {
        assertEquals(2, DigestAuthUtils.split("18/rod", "/").length);
        assertNull(DigestAuthUtils.split("18/rod", "!"));

        // only guarantees to split at FIRST delimiter, not EACH delimiter
        assertEquals(2, DigestAuthUtils.split("18|rod|foo|bar", "|").length);
    }


    public void testAuthorizationHeaderWithCommasIsSplitCorrectly() {
        String header = "Digest username=\"hamilton,bob\", realm=\"bobs,ok,realm\", nonce=\"the,nonce\", " +
                "uri=\"the,Uri\", response=\"the,response,Digest\", qop=theqop, nc=thenc, cnonce=\"the,cnonce\"";

        String[] parts = DigestAuthUtils.splitIgnoringQuotes(header, ',');

        assertEquals(8, parts.length);
    }
}
