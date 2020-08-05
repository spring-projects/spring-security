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
package org.springframework.security.ldap.userdetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.ApacheDsContainerConfig;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Filip Hanik
 * @author Eddú Meléndez
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
public class NestedLdapAuthoritiesPopulatorTests {

	@Autowired
	private ContextSource contextSource;

	private NestedLdapAuthoritiesPopulator populator;

	private LdapAuthority javaDevelopers;

	private LdapAuthority groovyDevelopers;

	private LdapAuthority scalaDevelopers;

	private LdapAuthority closureDevelopers;

	private LdapAuthority jDevelopers;

	private LdapAuthority circularJavaDevelopers;

	@Before
	public void setUp() {
		populator = new NestedLdapAuthoritiesPopulator(this.contextSource, "ou=jdeveloper");
		populator.setGroupSearchFilter("(member={0})");
		populator.setIgnorePartialResultException(false);
		populator.setRolePrefix("");
		populator.setSearchSubtree(true);
		populator.setConvertToUpperCase(false);
		jDevelopers = new LdapAuthority("j-developers", "cn=j-developers,ou=jdeveloper,dc=springframework,dc=org");
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
		DirContextAdapter ctx = new DirContextAdapter("uid=scaladude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "scaladude");
		assertThat(authorities).hasSize(5);
		assertThat(authorities).isEqualTo(
				Arrays.asList(javaDevelopers, circularJavaDevelopers, scalaDevelopers, groovyDevelopers, jDevelopers));
	}

	@Test
	public void testJavaDudeJDevelopersAuthorities() {
		DirContextAdapter ctx = new DirContextAdapter("uid=javadude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "javadude");
		assertThat(authorities).hasSize(4);
		assertThat(authorities).contains(javaDevelopers);
	}

	@Test
	public void testScalaDudeJDevelopersAuthoritiesWithSearchLimit() {
		populator.setMaxSearchDepth(1);
		DirContextAdapter ctx = new DirContextAdapter("uid=scaladude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "scaladude");
		assertThat(authorities).hasSize(1);
		assertThat(authorities).isEqualTo(Arrays.asList(scalaDevelopers));
	}

	@Test
	public void testGroovyDudeJDevelopersAuthorities() {
		DirContextAdapter ctx = new DirContextAdapter("uid=groovydude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "groovydude");
		assertThat(authorities).hasSize(4);
		assertThat(authorities)
				.isEqualTo(Arrays.asList(javaDevelopers, circularJavaDevelopers, groovyDevelopers, jDevelopers));
	}

	@Test
	public void testClosureDudeJDevelopersWithMembershipAsAttributeValues() {
		populator.setAttributeNames(new HashSet(Arrays.asList("member")));

		DirContextAdapter ctx = new DirContextAdapter("uid=closuredude,ou=people,dc=springframework,dc=org");
		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "closuredude");
		assertThat(authorities).hasSize(5);
		assertThat(authorities).isEqualTo(Arrays.asList(javaDevelopers, circularJavaDevelopers, closureDevelopers,
				groovyDevelopers, jDevelopers));

		LdapAuthority[] ldapAuthorities = authorities.toArray(new LdapAuthority[0]);
		assertThat(ldapAuthorities).hasSize(5);
		// groovy-developers group
		assertThat(ldapAuthorities[0].getAttributes().containsKey("member")).isTrue();
		assertThat(ldapAuthorities[0].getAttributes().get("member")).isNotNull();
		assertThat(ldapAuthorities[0].getAttributes().get("member")).hasSize(3);
		assertThat(ldapAuthorities[0].getFirstAttributeValue("member"))
				.isEqualTo("cn=groovy-developers,ou=jdeveloper,dc=springframework,dc=org");

		// java group
		assertThat(ldapAuthorities[1].getAttributes().containsKey("member")).isTrue();
		assertThat(ldapAuthorities[1].getAttributes().get("member")).isNotNull();
		assertThat(ldapAuthorities[1].getAttributes().get("member")).hasSize(3);
		assertThat(groovyDevelopers.getDn()).isEqualTo(ldapAuthorities[1].getFirstAttributeValue("member"));
		assertThat(ldapAuthorities[2].getAttributes().get("member"))
				.contains("uid=closuredude,ou=people,dc=springframework,dc=org");

		// test non existent attribute
		assertThat(ldapAuthorities[2].getFirstAttributeValue("test")).isNull();
		assertThat(ldapAuthorities[2].getAttributeValues("test")).isNotNull();
		assertThat(ldapAuthorities[2].getAttributeValues("test")).isEmpty();
		// test role name
		assertThat(ldapAuthorities[3].getAuthority()).isEqualTo(groovyDevelopers.getAuthority());
	}

}
