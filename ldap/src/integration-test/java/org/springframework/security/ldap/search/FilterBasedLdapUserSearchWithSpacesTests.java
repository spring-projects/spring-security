/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.ldap.search;

import javax.naming.ldap.LdapName;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Additional tests for {@link FilterBasedLdapUserSearch} with spaces in the base dn.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = FilterBasedLdapUserSearchWithSpacesTests.ApacheDsContainerWithSpacesConfig.class)
public class FilterBasedLdapUserSearchWithSpacesTests {

	@Autowired
	private DefaultSpringSecurityContextSource contextSource;

	// gh-9742
	@Test
	public void searchForUserWhenSpacesInBaseDnThenSuccess() throws Exception {
		FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=space cadets", "(uid={0})",
				this.contextSource);
		locator.setSearchSubtree(false);
		locator.setSearchTimeLimit(0);
		locator.setDerefLinkFlag(false);

		DirContextOperations bob = locator.searchForUser("space cadet");
		assertThat(bob.getStringAttribute("uid")).isEqualTo("space cadet");
		assertThat(bob.getDn()).isEqualTo(new LdapName("uid=space cadet,ou=space cadets"));
	}

	@Configuration
	static class ApacheDsContainerWithSpacesConfig implements DisposableBean {

		private ApacheDSContainer container;

		@Bean
		ApacheDSContainer ldapContainer() throws Exception {
			this.container = new ApacheDSContainer("dc=spring framework,dc=org",
					"classpath:test-server-with-spaces.ldif");
			this.container.setPort(0);
			return this.container;
		}

		@Bean
		ContextSource contextSource(ApacheDSContainer ldapContainer) {
			return new DefaultSpringSecurityContextSource(
					"ldap://127.0.0.1:" + ldapContainer.getLocalPort() + "/dc=spring%20framework,dc=org");
		}

		@Override
		public void destroy() {
			this.container.stop();
		}

	}

}
