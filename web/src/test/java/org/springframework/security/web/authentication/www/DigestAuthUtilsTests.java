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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.Map;

import org.junit.Test;
import org.springframework.util.StringUtils;

/**
 * Tests {@link org.springframework.security.util.StringSplitUtils}.
 *
 * @author Ben Alex
 */
public class DigestAuthUtilsTests {
	// ~ Constructors
	// ===================================================================================================

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testSplitEachArrayElementAndCreateMapNormalOperation() {
		// note it ignores malformed entries (ie those without an equals sign)
		String unsplit = "username=\"rod\", invalidEntryThatHasNoEqualsSign, realm=\"Contacts Realm\", nonce=\"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==\", uri=\"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4\", response=\"38644211cf9ac3da63ab639807e2baff\", qop=auth, nc=00000004, cnonce=\"2b8d329a8571b99a\"";
		String[] headerEntries = StringUtils.commaDelimitedListToStringArray(unsplit);
		Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(
				headerEntries, "=", "\"");

		assertThat(headerMap.get("username")).isEqualTo("rod");
		assertThat(headerMap.get("realm")).isEqualTo("Contacts Realm");
		assertThat(headerMap.get("nonce")).isEqualTo(
				"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==");
		assertThat(headerMap.get("uri")).isEqualTo(
				"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4");
		assertThat(headerMap.get("response")).isEqualTo(
				"38644211cf9ac3da63ab639807e2baff");
		assertThat(headerMap.get("qop")).isEqualTo("auth");
		assertThat(headerMap.get("nc")).isEqualTo("00000004");
		assertThat(headerMap.get("cnonce")).isEqualTo("2b8d329a8571b99a");
		assertThat(headerMap).hasSize(8);
	}

	@Test
	public void testSplitEachArrayElementAndCreateMapRespectsInstructionNotToRemoveCharacters() {
		String unsplit = "username=\"rod\", realm=\"Contacts Realm\", nonce=\"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==\", uri=\"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4\", response=\"38644211cf9ac3da63ab639807e2baff\", qop=auth, nc=00000004, cnonce=\"2b8d329a8571b99a\"";
		String[] headerEntries = StringUtils.commaDelimitedListToStringArray(unsplit);
		Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(
				headerEntries, "=", null);

		assertThat(headerMap.get("username")).isEqualTo("\"rod\"");
		assertThat(headerMap.get("realm")).isEqualTo("\"Contacts Realm\"");
		assertThat(headerMap.get("nonce")).isEqualTo(
				"\"MTEwOTAyMzU1MTQ4NDo1YzY3OWViYWM5NDNmZWUwM2UwY2NmMDBiNDQzMTQ0OQ==\"");
		assertThat(headerMap.get("uri")).isEqualTo(
				"\"/spring-security-sample-contacts-filter/secure/adminPermission.htm?contactId=4\"");
		assertThat(headerMap.get("response")).isEqualTo(
				"\"38644211cf9ac3da63ab639807e2baff\"");
		assertThat(headerMap.get("qop")).isEqualTo("auth");
		assertThat(headerMap.get("nc")).isEqualTo("00000004");
		assertThat(headerMap.get("cnonce")).isEqualTo("\"2b8d329a8571b99a\"");
		assertThat(headerMap).hasSize(8);
	}

	@Test
	public void testSplitEachArrayElementAndCreateMapReturnsNullIfArrayEmptyOrNull() {
		assertThat(DigestAuthUtils.splitEachArrayElementAndCreateMap(null, "=",
				"\"")).isNull();
		assertThat(DigestAuthUtils.splitEachArrayElementAndCreateMap(new String[] {}, "=",
				"\"")).isNull();
	}

	@Test
	public void testSplitNormalOperation() {
		String unsplit = "username=\"rod==\"";
		assertThat(DigestAuthUtils.split(unsplit, "=")[0]).isEqualTo("username");
		assertThat(DigestAuthUtils.split(unsplit, "=")[1]).isEqualTo("\"rod==\"");// should
																					// not
																					// remove
																					// quotes
																					// or
																					// extra
																					// equals
	}

	@Test
	public void testSplitRejectsNullsAndIncorrectLengthStrings() {
		try {
			DigestAuthUtils.split(null, "="); // null
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			DigestAuthUtils.split("", "="); // empty string
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			DigestAuthUtils.split("sdch=dfgf", null); // null
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			DigestAuthUtils.split("fvfv=dcdc", ""); // empty string
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			DigestAuthUtils.split("dfdc=dcdc", "BIGGER_THAN_ONE_CHARACTER");
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testSplitWorksWithDifferentDelimiters() {
		assertThat(DigestAuthUtils.split("18/rod", "/")).hasSize(2);
		assertThat(DigestAuthUtils.split("18/rod", "!")).isNull();

		// only guarantees to split at FIRST delimiter, not EACH delimiter
		assertThat(DigestAuthUtils.split("18|rod|foo|bar", "|")).hasSize(2);
	}

	public void testAuthorizationHeaderWithCommasIsSplitCorrectly() {
		String header = "Digest username=\"hamilton,bob\", realm=\"bobs,ok,realm\", nonce=\"the,nonce\", "
				+ "uri=\"the,Uri\", response=\"the,response,Digest\", qop=theqop, nc=thenc, cnonce=\"the,cnonce\"";

		String[] parts = DigestAuthUtils.splitIgnoringQuotes(header, ',');

		assertThat(parts).hasSize(8);
	}
}
