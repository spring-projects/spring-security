/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.ldap.server;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests reproducing problems with loading structures from ldif on embedded ApacheDS
 * server.
 *
 * @author Marcin Zajączkowski
 */
public class ApacheDSEmbeddedLdifTests {

	private static final String LDAP_ROOT = "ou=ssattributes,dc=springframework,dc=org";
	private static final int LDAP_PORT = 52389;

	private ApacheDSContainer server;
	private SpringSecurityLdapTemplate ldapTemplate;

	@Before
	public void setUp() throws Exception {
		// TODO: InMemoryXmlApplicationContext would be useful here, but it is not visible
		this.server = new ApacheDSContainer(LDAP_ROOT,
				"classpath:test-server-custom-attribute-types.ldif");
		this.server.setPort(LDAP_PORT);
		this.server.afterPropertiesSet();

		this.ldapTemplate = new SpringSecurityLdapTemplate(createLdapContextSource());
	}

	private LdapContextSource createLdapContextSource() {
		LdapContextSource ldapContextSource = new LdapContextSource();
		ldapContextSource.setUrl("ldap://localhost:" + LDAP_PORT);
		ldapContextSource.setBase(LDAP_ROOT);
		ldapContextSource.afterPropertiesSet();
		return ldapContextSource;
	}

	@After
	public void tearDown() throws Exception {
		if (this.server != null) {
			this.server.destroy();
		}
	}

	@Ignore // Not fixed yet
	@Test // SEC-2387
	public void customAttributeTypesShouldBeProperlyCreatedWhenLoadedFromLdif() {
		assertThat(this.ldapTemplate.compare("uid=objectWithCustomAttribute1", "uid",
				"objectWithCustomAttribute1")).isTrue();
		assertThat(this.ldapTemplate.compare("uid=objectWithCustomAttribute1",
				"customAttribute", "I am custom")).isTrue();
	}

}
