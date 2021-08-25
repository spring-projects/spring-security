/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.config.ldap;

import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.ldap.userdetails.Person;
import org.springframework.security.ldap.userdetails.PersonContextMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 * @author Rob Winch
 * @author Eddú Meléndez
 */
public class LdapUserServiceBeanDefinitionParserTests {

	private InMemoryXmlApplicationContext appCtx;

	@AfterEach
	public void closeAppContext() {
		if (this.appCtx != null) {
			this.appCtx.close();
			this.appCtx = null;
		}
	}

	@Test
	public void beanClassNamesAreCorrect() {
		assertThat(FilterBasedLdapUserSearch.class.getName())
				.isEqualTo(LdapUserServiceBeanDefinitionParser.LDAP_SEARCH_CLASS);
		assertThat(PersonContextMapper.class.getName())
				.isEqualTo(LdapUserServiceBeanDefinitionParser.PERSON_MAPPER_CLASS);
		assertThat(InetOrgPersonContextMapper.class.getName())
				.isEqualTo(LdapUserServiceBeanDefinitionParser.INET_ORG_PERSON_MAPPER_CLASS);
		assertThat(LdapUserDetailsMapper.class.getName())
				.isEqualTo(LdapUserServiceBeanDefinitionParser.LDAP_USER_MAPPER_CLASS);
		assertThat(DefaultLdapAuthoritiesPopulator.class.getName())
				.isEqualTo(LdapUserServiceBeanDefinitionParser.LDAP_AUTHORITIES_POPULATOR_CLASS);
		assertThat(new LdapUserServiceBeanDefinitionParser().getBeanClassName(mock(Element.class)))
				.isEqualTo(LdapUserDetailsService.class.getName());
	}

	@Test
	public void minimalConfigurationIsParsedOk() {
		setContext(
				"<ldap-user-service user-search-filter='(uid={0})' /><ldap-server ldif='classpath:test-server.ldif' url='ldap://127.0.0.1:343/dc=springframework,dc=org' />");
	}

	@Test
	public void userServiceReturnsExpectedData() {
		setContext(
				"<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-search-filter='member={0}' /><ldap-server ldif='classpath:test-server.ldif'/>");

		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails ben = uds.loadUserByUsername("ben");

		Set<String> authorities = AuthorityUtils.authorityListToSet(ben.getAuthorities());
		assertThat(authorities).hasSize(3);
		assertThat(authorities.contains("ROLE_DEVELOPERS")).isTrue();
	}

	@Test
	public void differentUserSearchBaseWorksAsExpected() {
		setContext("<ldap-user-service id='ldapUDS' " + "       user-search-base='ou=otherpeople' "
				+ "       user-search-filter='(cn={0})' "
				+ "       group-search-filter='member={0}' /><ldap-server ldif='classpath:test-server.ldif'/>");

		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails joe = uds.loadUserByUsername("Joe Smeth");

		assertThat(joe.getUsername()).isEqualTo("Joe Smeth");
	}

	@Test
	public void rolePrefixIsSupported() {
		setContext("<ldap-user-service id='ldapUDS' " + "     user-search-filter='(uid={0})' "
				+ "     group-search-filter='member={0}' role-prefix='PREFIX_'/>"
				+ "<ldap-user-service id='ldapUDSNoPrefix' " + "     user-search-filter='(uid={0})' "
				+ "     group-search-filter='member={0}' role-prefix='none'/><ldap-server ldif='classpath:test-server.ldif'/>");

		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails ben = uds.loadUserByUsername("ben");
		assertThat(AuthorityUtils.authorityListToSet(ben.getAuthorities())).contains("PREFIX_DEVELOPERS");

		uds = (UserDetailsService) this.appCtx.getBean("ldapUDSNoPrefix");
		ben = uds.loadUserByUsername("ben");
		assertThat(AuthorityUtils.authorityListToSet(ben.getAuthorities())).contains("DEVELOPERS");
	}

	@Test
	public void differentGroupRoleAttributeWorksAsExpected() {
		setContext(
				"<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-role-attribute='ou' group-search-filter='member={0}' /><ldap-server ldif='classpath:test-server.ldif'/>");

		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails ben = uds.loadUserByUsername("ben");

		Set<String> authorities = AuthorityUtils.authorityListToSet(ben.getAuthorities());
		assertThat(authorities).hasSize(3);
		assertThat(authorities.contains("ROLE_DEVELOPER")).isTrue();

	}

	@Test
	public void isSupportedByAuthenticationProviderElement() {
		setContext(
				"<ldap-server url='ldap://127.0.0.1:343/dc=springframework,dc=org' ldif='classpath:test-server.ldif'/>"
						+ "<authentication-manager>" + "  <authentication-provider>"
						+ "    <ldap-user-service user-search-filter='(uid={0})' />" + "  </authentication-provider>"
						+ "</authentication-manager>");
	}

	@Test
	public void personContextMapperIsSupported() {
		setContext("<ldap-server ldif='classpath:test-server.ldif'/>"
				+ "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-details-class='person'/>");
		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails ben = uds.loadUserByUsername("ben");
		assertThat(ben instanceof Person).isTrue();
	}

	@Test
	public void inetOrgContextMapperIsSupported() {
		setContext("<ldap-server id='someServer' ldif='classpath:test-server.ldif'/>"
				+ "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-details-class='inetOrgPerson'/>");
		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails ben = uds.loadUserByUsername("ben");
		assertThat(ben instanceof InetOrgPerson).isTrue();
	}

	@Test
	public void externalContextMapperIsSupported() {
		setContext("<ldap-server id='someServer' ldif='classpath:test-server.ldif'/>"
				+ "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-context-mapper-ref='mapper'/>"
				+ "<b:bean id='mapper' class='" + InetOrgPersonContextMapper.class.getName() + "'/>");

		UserDetailsService uds = (UserDetailsService) this.appCtx.getBean("ldapUDS");
		UserDetails ben = uds.loadUserByUsername("ben");
		assertThat(ben instanceof InetOrgPerson).isTrue();
	}

	private void setContext(String context) {
		this.appCtx = new InMemoryXmlApplicationContext(context);
	}

}
