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
package org.springframework.security.ldap.userdetails;

import org.junit.Before;
import org.junit.Test;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import static org.junit.Assert.*;

/**
 * @author Filip Hanik
 */
public class NestedLdapAuthoritiesPopulatorTests extends AbstractLdapIntegrationTests {

	private NestedLdapAuthoritiesPopulator populator;
	private LdapAuthority javaDevelopers;
	private LdapAuthority groovyDevelopers;
	private LdapAuthority scalaDevelopers;
	private LdapAuthority closureDevelopers;
	private LdapAuthority jDevelopers;
	private LdapAuthority circularJavaDevelopers;

	// ~ Methods
	// ========================================================================================================

	@Before
	public void setUp() throws Exception {
		populator = new NestedLdapAuthoritiesPopulator(getContextSource(),
				"ou=jdeveloper");
		populator.setGroupSearchFilter("(member={0})");
		populator.setIgnorePartialResultException(false);
		populator.setRolePrefix("");
		populator.setSearchSubtree(true);
		populator.setConvertToUpperCase(false);
		jDevelopers = new LdapAuthority("j-developers",
				"cn=j-developers,ou=jdeveloper,dc=springframework,dc=org");
		javaDevelopers = new LdapAuthority("java-developers",
				"cn=java-developers,ou=jdeveloper,dc=springframework,dc=org");
		groovyDevelopers = new LdapAuthority("groovy-developers",
				"cn=groovy-developers,ou=jdeveloper,dc=springframework,dc=org");
		scalaDevelopers = new LdapAuthority("scala-developers",
				"cn=scala-developers,ou=jdeveloper,dc=springframework,dc=org");
		closureDevelopers = new LdapAuthority("closure-developers",
				"cn=closure-developers,ou=jdeveloper,dc=springframework,dc=org");
		circularJavaDevelopers = new LdapAuthority("circular-java-developers",
				"cn=circular-java-developers,ou=jdeveloper,dc=springframework,dc=org");
	}

	@Test
	public void testScalaDudeJDevelopersAuthorities() {
		DirContextAdapter ctx = new DirContextAdapter(
				"uid=scaladude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx,
				"scaladude");
		assertEquals(5, authorities.size());
		assertEquals(Arrays.asList(javaDevelopers, scalaDevelopers,
				circularJavaDevelopers, jDevelopers, groovyDevelopers), authorities);
	}

	@Test
	public void testJavaDudeJDevelopersAuthorities() {
		DirContextAdapter ctx = new DirContextAdapter(
				"uid=javadude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx,
				"javadude");
		assertEquals(3, authorities.size());
		assertEquals(Arrays.asList(javaDevelopers, circularJavaDevelopers, jDevelopers),
				authorities);
	}

	@Test
	public void testScalaDudeJDevelopersAuthoritiesWithSearchLimit() {
		populator.setMaxSearchDepth(1);
		DirContextAdapter ctx = new DirContextAdapter(
				"uid=scaladude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx,
				"scaladude");
		assertEquals(1, authorities.size());
		assertEquals(Arrays.asList(scalaDevelopers), authorities);
	}

	@Test
	public void testGroovyDudeJDevelopersAuthorities() {
		DirContextAdapter ctx = new DirContextAdapter(
				"uid=groovydude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx,
				"groovydude");
		assertEquals(4, authorities.size());
		assertEquals(Arrays.asList(javaDevelopers, circularJavaDevelopers, jDevelopers,
				groovyDevelopers), authorities);
	}

	@Test
	public void testClosureDudeJDevelopersWithMembershipAsAttributeValues() {
		populator.setAttributeNames(new HashSet(Arrays.asList("member")));

		DirContextAdapter ctx = new DirContextAdapter(
				"uid=closuredude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx,
				"closuredude");
		assertEquals(5, authorities.size());
		assertEquals(Arrays.asList(closureDevelopers, javaDevelopers,
				circularJavaDevelopers, jDevelopers, groovyDevelopers), authorities);

		LdapAuthority[] ldapAuthorities = authorities.toArray(new LdapAuthority[0]);
		assertEquals(5, ldapAuthorities.length);
		// closure group
		assertTrue(ldapAuthorities[0].getAttributes().containsKey("member"));
		assertNotNull(ldapAuthorities[0].getAttributes().get("member"));
		assertEquals(1, ldapAuthorities[0].getAttributes().get("member").size());
		assertEquals("uid=closuredude,ou=people,dc=springframework,dc=org",
				ldapAuthorities[0].getFirstAttributeValue("member"));

		// java group
		assertTrue(ldapAuthorities[1].getAttributes().containsKey("member"));
		assertNotNull(ldapAuthorities[1].getAttributes().get("member"));
		assertEquals(3, ldapAuthorities[1].getAttributes().get("member").size());
		assertEquals(groovyDevelopers.getDn(),
				ldapAuthorities[1].getFirstAttributeValue("member"));
		assertEquals(new String[] { groovyDevelopers.getDn(), scalaDevelopers.getDn(),
				"uid=javadude,ou=people,dc=springframework,dc=org" }, ldapAuthorities[1]
				.getAttributes().get("member"));

		// test non existent attribute
		assertNull(ldapAuthorities[2].getFirstAttributeValue("test"));
		assertNotNull(ldapAuthorities[2].getAttributeValues("test"));
		assertEquals(0, ldapAuthorities[2].getAttributeValues("test").size());
		// test role name
		assertEquals(jDevelopers.getAuthority(), ldapAuthorities[3].getAuthority());
	}
}
