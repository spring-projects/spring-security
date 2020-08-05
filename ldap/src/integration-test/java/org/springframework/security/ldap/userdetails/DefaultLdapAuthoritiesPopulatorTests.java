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

import static org.assertj.core.api.Assertions.*;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.ApacheDsContainerConfig;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ApacheDsContainerConfig.class)
@SuppressWarnings({ "deprecation" })
public class DefaultLdapAuthoritiesPopulatorTests {

	@Autowired
	private ContextSource contextSource;

	private DefaultLdapAuthoritiesPopulator populator;

	// ~ Methods
	// ========================================================================================================

	@Before
	public void setUp() {
		populator = new DefaultLdapAuthoritiesPopulator(this.contextSource, "ou=groups");
		populator.setIgnorePartialResultException(false);
	}

	@Test
	public void defaultRoleIsAssignedWhenSet() {
		populator.setDefaultRole("ROLE_USER");
		assertThat(populator.getContextSource()).isSameAs(this.contextSource);

		DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("cn=notfound"));

		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "notfound");
		assertThat(authorities).hasSize(1);
		assertThat(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_USER")).isTrue();
	}

	@Test
	public void nullSearchBaseIsAccepted() {
		populator = new DefaultLdapAuthoritiesPopulator(this.contextSource, null);
		populator.setDefaultRole("ROLE_USER");

		Collection<GrantedAuthority> authorities = populator
				.getGrantedAuthorities(new DirContextAdapter(new DistinguishedName("cn=notused")), "notused");
		assertThat(authorities).hasSize(1);
		assertThat(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_USER")).isTrue();
	}

	@Test
	public void groupSearchReturnsExpectedRoles() {
		populator.setRolePrefix("ROLE_");
		populator.setGroupRoleAttribute("ou");
		populator.setSearchSubtree(true);
		populator.setSearchSubtree(false);
		populator.setConvertToUpperCase(true);
		populator.setGroupSearchFilter("(member={0})");

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

		Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "ben"));

		assertThat(authorities).as("Should have 2 roles").hasSize(2);

		assertThat(authorities.contains("ROLE_DEVELOPER")).isTrue();
		assertThat(authorities.contains("ROLE_MANAGER")).isTrue();
	}

	@Test
	public void useOfUsernameParameterReturnsExpectedRoles() {
		populator.setGroupRoleAttribute("ou");
		populator.setConvertToUpperCase(true);
		populator.setGroupSearchFilter("(ou={1})");

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

		Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "manager"));

		assertThat(authorities).as("Should have 1 role").hasSize(1);
		assertThat(authorities.contains("ROLE_MANAGER")).isTrue();
	}

	@Test
	public void subGroupRolesAreNotFoundByDefault() {
		populator.setGroupRoleAttribute("ou");
		populator.setConvertToUpperCase(true);

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

		Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "manager"));

		assertThat(authorities).as("Should have 2 roles").hasSize(2);
		assertThat(authorities.contains("ROLE_MANAGER")).isTrue();
		assertThat(authorities.contains("ROLE_DEVELOPER")).isTrue();
	}

	@Test
	public void subGroupRolesAreFoundWhenSubtreeSearchIsEnabled() {
		populator.setGroupRoleAttribute("ou");
		populator.setConvertToUpperCase(true);
		populator.setSearchSubtree(true);

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

		Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "manager"));

		assertThat(authorities).as("Should have 3 roles").hasSize(3);
		assertThat(authorities.contains("ROLE_MANAGER")).isTrue();
		assertThat(authorities.contains("ROLE_SUBMANAGER")).isTrue();
		assertThat(authorities.contains("ROLE_DEVELOPER")).isTrue();
	}

	@Test
	public void extraRolesAreAdded() {
		populator = new DefaultLdapAuthoritiesPopulator(this.contextSource, null) {
			@Override
			protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
				return new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_EXTRA"));
			}
		};

		Collection<GrantedAuthority> authorities = populator
				.getGrantedAuthorities(new DirContextAdapter(new DistinguishedName("cn=notused")), "notused");
		assertThat(authorities).hasSize(1);
		assertThat(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_EXTRA")).isTrue();
	}

	@Test
	public void userDnWithEscapedCharacterParameterReturnsExpectedRoles() {
		populator.setGroupRoleAttribute("ou");
		populator.setConvertToUpperCase(true);
		populator.setGroupSearchFilter("(member={0})");

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("cn=mouse\\, jerry,ou=people,dc=springframework,dc=org"));

		Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "notused"));

		assertThat(authorities).as("Should have 1 role").hasSize(1);
		assertThat(authorities.contains("ROLE_MANAGER")).isTrue();
	}

	@Test
	public void customAuthoritiesMappingFunction() {
		populator.setAuthorityMapper(record -> {
			String dn = record.get(SpringSecurityLdapTemplate.DN_KEY).get(0);
			String role = record.get(populator.getGroupRoleAttribute()).get(0);
			return new LdapAuthority(role, dn);
		});

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("cn=mouse\\, jerry,ou=people,dc=springframework,dc=org"));

		Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "notused");

		assertThat(authorities).allMatch(LdapAuthority.class::isInstance);
	}

	@Test(expected = IllegalArgumentException.class)
	public void customAuthoritiesMappingFunctionThrowsIfNull() {
		populator.setAuthorityMapper(null);
	}

}
