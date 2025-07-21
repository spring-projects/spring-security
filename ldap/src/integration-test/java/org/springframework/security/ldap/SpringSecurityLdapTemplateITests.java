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

package org.springframework.security.ldap;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.UncategorizedLdapException;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = UnboundIdContainerConfig.class)
// FIXME: See https://github.com/spring-projects/spring-security/issues/17543
@DirtiesContext
public class SpringSecurityLdapTemplateITests {

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	private SpringSecurityLdapTemplate template;

	@BeforeEach
	public void setUp() {
		this.template = new SpringSecurityLdapTemplate(this.contextSource);
	}

	@Test
	public void compareOfCorrectValueSucceeds() {
		assertThat(this.template.compare("uid=bob,ou=people", "uid", "bob")).isTrue();
	}

	@Test
	public void compareOfCorrectByteValueSucceeds() {
		assertThat(this.template.compare("uid=bob,ou=people", "userPassword", Utf8.encode("bobspassword"))).isTrue();
	}

	@Test
	public void compareOfWrongByteValueFails() {
		assertThat(this.template.compare("uid=bob,ou=people", "userPassword", Utf8.encode("wrongvalue"))).isFalse();
	}

	@Test
	public void compareOfWrongValueFails() {
		assertThat(this.template.compare("uid=bob,ou=people", "uid", "wrongvalue")).isFalse();
	}

	// @Test
	// public void testNameExistsForInValidNameFails() {
	// assertThat(template.nameExists("ou=doesntexist,dc=springframework,dc=org")).isFalse();
	// }
	//
	// @Test
	// public void testNameExistsForValidNameSucceeds() {
	// assertThat(template.nameExists("ou=groups,dc=springframework,dc=org")).isTrue();
	// }

	@Test
	public void namingExceptionIsTranslatedCorrectly() {
		assertThatExceptionOfType(UncategorizedLdapException.class)
			.isThrownBy(() -> this.template.executeReadOnly((ContextExecutor) (dirContext) -> {
				throw new NamingException();
			}));
	}

	@Test
	public void roleSearchReturnsCorrectNumberOfRoles() {
		String param = "uid=ben,ou=people,dc=springframework,dc=org";

		Set<String> values = this.template.searchForSingleAttributeValues("ou=groups", "(member={0})",
				new String[] { param }, "ou");

		assertThat(values).as("Expected 3 results from search").hasSize(3);
		assertThat(values).contains("developer");
		assertThat(values).contains("manager");
		assertThat(values).contains("submanager");
	}

	@Test
	public void testMultiAttributeRetrievalWithNullAttributeNames() {
		Set<Map<String, List<String>>> values = this.template.searchForMultipleAttributeValues("ou=people", "(uid={0})",
				new String[] { "bob" }, null);
		assertThat(values).hasSize(1);
		Map<String, List<String>> record = values.iterator().next();
		assertAttributeValue(record, "uid", "bob");
		assertAttributeValue(record, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson");
		assertAttributeValue(record, "cn", "Bob Hamilton");
		assertAttributeValue(record, "sn", "Hamilton");
		assertThat(record.containsKey("userPassword")).isTrue();
	}

	@Test
	public void testMultiAttributeRetrievalWithZeroLengthAttributeNames() {
		Set<Map<String, List<String>>> values = this.template.searchForMultipleAttributeValues("ou=people", "(uid={0})",
				new String[] { "bob" }, new String[0]);
		assertThat(values).hasSize(1);
		Map<String, List<String>> record = values.iterator().next();
		assertAttributeValue(record, "uid", "bob");
		assertAttributeValue(record, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson");
		assertAttributeValue(record, "cn", "Bob Hamilton");
		assertAttributeValue(record, "sn", "Hamilton");
		assertThat(record.containsKey("userPassword")).isTrue();
	}

	@Test
	public void testMultiAttributeRetrievalWithSpecifiedAttributeNames() {
		Set<Map<String, List<String>>> values = this.template.searchForMultipleAttributeValues("ou=people", "(uid={0})",
				new String[] { "bob" }, new String[] { "uid", "cn", "sn" });
		assertThat(values).hasSize(1);
		Map<String, List<String>> record = values.iterator().next();
		assertAttributeValue(record, "uid", "bob");
		assertAttributeValue(record, "cn", "Bob Hamilton");
		assertAttributeValue(record, "sn", "Hamilton");
		assertThat(record.containsKey("userPassword")).isFalse();
		assertThat(record.containsKey("objectClass")).isFalse();
	}

	protected void assertAttributeValue(Map<String, List<String>> record, String attributeName, String... values) {
		assertThat(record).containsKey(attributeName);
		assertThat(record.get(attributeName)).hasSize(values.length);
		for (int i = 0; i < values.length; i++) {
			assertThat(record.get(attributeName).get(i)).isEqualTo(values[i]);
		}
	}

	@Test
	public void testRoleSearchForMissingAttributeFailsGracefully() {
		String param = "uid=ben,ou=people,dc=springframework,dc=org";

		Set<String> values = this.template.searchForSingleAttributeValues("ou=groups", "(member={0})",
				new String[] { param }, "mail");

		assertThat(values).isEmpty();
	}

	@Test
	public void roleSearchWithEscapedCharacterSucceeds() {
		String param = "cn=mouse\\, jerry,ou=people,dc=springframework,dc=org";

		Set<String> values = this.template.searchForSingleAttributeValues("ou=groups", "(member={0})",
				new String[] { param }, "cn");

		assertThat(values).hasSize(1);
	}

	@Test
	public void nonSpringLdapSearchCodeTestMethod() throws Exception {
		java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, this.contextSource.getUrls()[0]);
		env.put(Context.SECURITY_PRINCIPAL, "");
		env.put(Context.SECURITY_CREDENTIALS, "");

		DirContext ctx = new javax.naming.directory.InitialDirContext(env);
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningObjFlag(true);
		controls.setReturningAttributes(null);
		String param = "cn=mouse\\, jerry,ou=people,dc=springframework,dc=org";

		javax.naming.NamingEnumeration<SearchResult> results = ctx.search("ou=groups,dc=springframework,dc=org",
				"(member={0})", new String[] { param }, controls);

		assertThat(results.hasMore()).as("Expected a result").isTrue();
	}

	@Test
	public void searchForSingleEntryWithEscapedCharsInDnSucceeds() {
		String param = "mouse, jerry";

		this.template.searchForSingleEntry("ou=people", "(cn={0})", new String[] { param });
	}

}
