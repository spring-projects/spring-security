/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dayan Kodippily
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(
		classes = DefaultLdapAuthoritiesPopulatorGetGrantedAuthoritiesTests.ApacheDsContainerWithUndefinedGroupRoleAttributeConfig.class)
public class DefaultLdapAuthoritiesPopulatorGetGrantedAuthoritiesTests {

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	private DefaultLdapAuthoritiesPopulator populator;

	@BeforeEach
	public void setUp() {
		this.populator = new DefaultLdapAuthoritiesPopulator(this.contextSource, "ou=groups");
		this.populator.setIgnorePartialResultException(false);
	}

	@Test
	public void groupSearchDoesNotAllowNullRoles() {
		this.populator.setRolePrefix("ROLE_");
		this.populator.setGroupRoleAttribute("ou");
		this.populator.setSearchSubtree(true);
		this.populator.setSearchSubtree(false);
		this.populator.setConvertToUpperCase(true);
		this.populator.setGroupSearchFilter("(member={0})");

		DirContextAdapter ctx = new DirContextAdapter(
				new DistinguishedName("uid=dayan,ou=people,dc=springframework,dc=org"));

		Set<String> authorities = AuthorityUtils.authorityListToSet(this.populator.getGrantedAuthorities(ctx, "dayan"));

		assertThat(authorities).as("Should have 1 role").hasSize(2);

		assertThat(authorities).contains("ROLE_DEVELOPER");
		assertThat(authorities).contains("ROLE_");
	}

	@Configuration
	static class ApacheDsContainerWithUndefinedGroupRoleAttributeConfig implements DisposableBean {

		private ApacheDSContainer container;

		@Bean
		ApacheDSContainer ldapContainer() throws Exception {
			this.container = new ApacheDSContainer("dc=springframework,dc=org",
					"classpath:test-server-with-undefined-group-role-attributes.ldif");
			this.container.setPort(0);
			return this.container;
		}

		@Bean
		ContextSource contextSource(ApacheDSContainer ldapContainer) {
			return new DefaultSpringSecurityContextSource(
					"ldap://127.0.0.1:" + ldapContainer.getLocalPort() + "/dc=springframework,dc=org");
		}

		@Override
		public void destroy() {
			this.container.stop();
		}

	}

}
