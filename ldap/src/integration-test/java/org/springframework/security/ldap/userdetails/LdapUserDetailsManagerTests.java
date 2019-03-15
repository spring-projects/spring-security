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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

/**
 * @author Luke Taylor
 */
public class LdapUserDetailsManagerTests extends AbstractLdapIntegrationTests {

	private static final List<GrantedAuthority> TEST_AUTHORITIES = AuthorityUtils.createAuthorityList(
			"ROLE_CLOWNS", "ROLE_ACROBATS");

	private LdapUserDetailsManager mgr;

	private SpringSecurityLdapTemplate template;

	@Before
	public void setUp() throws Exception {
		mgr = new LdapUserDetailsManager(getContextSource());
		template = new SpringSecurityLdapTemplate(getContextSource());
		DirContextAdapter ctx = new DirContextAdapter();

		ctx.setAttributeValue("objectclass", "organizationalUnit");
		ctx.setAttributeValue("ou", "test people");
		template.bind("ou=test people", ctx, null);

		ctx.setAttributeValue("ou", "testgroups");
		template.bind("ou=testgroups", ctx, null);

		DirContextAdapter group = new DirContextAdapter();

		group.setAttributeValue("objectclass", "groupOfNames");
		group.setAttributeValue("cn", "clowns");
		group.setAttributeValue("member",
				"cn=nobody,ou=test people,dc=springframework,dc=org");
		template.bind("cn=clowns,ou=testgroups", group, null);

		group.setAttributeValue("cn", "acrobats");
		template.bind("cn=acrobats,ou=testgroups", group, null);

		mgr.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=test people", "uid"));
		mgr.setGroupSearchBase("ou=testgroups");
		mgr.setGroupRoleAttributeName("cn");
		mgr.setGroupMemberAttributeName("member");
		mgr.setUserDetailsMapper(new PersonContextMapper());
	}

	@After
	public void onTearDown() throws Exception {
		// Iterator people = template.list("ou=testpeople").iterator();

		// DirContext rootCtx = new DirContextAdapter(new
		// DistinguishedName(getInitialCtxFactory().getRootDn()));
		//
		// while(people.hasNext()) {
		// template.unbind((String) people.next() + ",ou=testpeople");
		// }

		template.unbind("ou=test people", true);
		template.unbind("ou=testgroups", true);

		SecurityContextHolder.clearContext();
	}

	@Test
	public void testLoadUserByUsernameReturnsCorrectData() {
		mgr.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=people", "uid"));
		mgr.setGroupSearchBase("ou=groups");
		LdapUserDetails bob = (LdapUserDetails) mgr.loadUserByUsername("bob");
		assertThat(bob.getUsername()).isEqualTo("bob");
		assertThat(bob.getDn()).isEqualTo("uid=bob,ou=people,dc=springframework,dc=org");
		assertThat(bob.getPassword()).isEqualTo("bobspassword");

		assertThat(bob.getAuthorities()).hasSize(1);
	}

	@Test(expected = UsernameNotFoundException.class)
	public void testLoadingInvalidUsernameThrowsUsernameNotFoundException() {
		mgr.loadUserByUsername("jim");
	}

	@Test
	public void testUserExistsReturnsTrueForValidUser() {
		mgr.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=people", "uid"));
		assertThat(mgr.userExists("bob")).isTrue();
	}

	@Test
	public void testUserExistsReturnsFalseForInValidUser() {
		assertThat(mgr.userExists("jim")).isFalse();
	}

	@Test
	public void testCreateNewUserSucceeds() {
		InetOrgPerson.Essence p = new InetOrgPerson.Essence();
		p.setCarLicense("XXX");
		p.setCn(new String[] { "Joe Smeth" });
		p.setDepartmentNumber("5679");
		p.setDescription("Some description");
		p.setDn("whocares");
		p.setEmployeeNumber("E781");
		p.setInitials("J");
		p.setMail("joe@smeth.com");
		p.setMobile("+44776542911");
		p.setOu("Joes Unit");
		p.setO("Organization");
		p.setRoomNumber("500X");
		p.setSn("Smeth");
		p.setUid("joe");

		p.setAuthorities(TEST_AUTHORITIES);

		mgr.createUser(p.createUserDetails());
	}

	@Test
	public void testDeleteUserSucceeds() {
		InetOrgPerson.Essence p = new InetOrgPerson.Essence();
		p.setDn("whocares");
		p.setCn(new String[] { "Don Smeth" });
		p.setSn("Smeth");
		p.setUid("don");
		p.setAuthorities(TEST_AUTHORITIES);

		mgr.createUser(p.createUserDetails());
		mgr.setUserDetailsMapper(new InetOrgPersonContextMapper());

		InetOrgPerson don = (InetOrgPerson) mgr.loadUserByUsername("don");

		assertThat(don.getAuthorities()).hasSize(2);

		mgr.deleteUser("don");

		try {
			mgr.loadUserByUsername("don");
			fail("Expected UsernameNotFoundException after deleting user");
		}
		catch (UsernameNotFoundException expected) {
			// expected
		}

		// Check that no authorities are left
		assertThat(
				mgr.getUserAuthorities(mgr.usernameMapper.buildDn("don"), "don")).hasSize(
						0);
	}

	@Test
	public void testPasswordChangeWithCorrectOldPasswordSucceeds() {
		InetOrgPerson.Essence p = new InetOrgPerson.Essence();
		p.setDn("whocares");
		p.setCn(new String[] { "John Yossarian" });
		p.setSn("Yossarian");
		p.setUid("johnyossarian");
		p.setPassword("yossarianspassword");
		p.setAuthorities(TEST_AUTHORITIES);

		mgr.createUser(p.createUserDetails());

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("johnyossarian",
						"yossarianspassword", TEST_AUTHORITIES));

		mgr.changePassword("yossarianspassword", "yossariansnewpassword");

		assertThat(template.compare("uid=johnyossarian,ou=test people", "userPassword",
				"yossariansnewpassword")).isTrue();
	}

	@Test(expected = BadCredentialsException.class)
	public void testPasswordChangeWithWrongOldPasswordFails() {
		InetOrgPerson.Essence p = new InetOrgPerson.Essence();
		p.setDn("whocares");
		p.setCn(new String[] { "John Yossarian" });
		p.setSn("Yossarian");
		p.setUid("johnyossarian");
		p.setPassword("yossarianspassword");
		p.setAuthorities(TEST_AUTHORITIES);

		mgr.createUser(p.createUserDetails());

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("johnyossarian",
						"yossarianspassword", TEST_AUTHORITIES));

		mgr.changePassword("wrongpassword", "yossariansnewpassword");
	}
}
