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
package org.springframework.security.ldap.userdetails;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Filip Hanik
 */
public class LdapAuthorityTests {

	public static final String DN = "cn=filip,ou=Users,dc=test,dc=com";

	LdapAuthority authority;

	@Before
	public void setUp() {
		Map<String, List<String>> attributes = new HashMap<>();
		attributes.put(SpringSecurityLdapTemplate.DN_KEY, Arrays.asList(DN));
		attributes.put("mail", Arrays.asList("filip@ldap.test.org", "filip@ldap.test2.org"));
		authority = new LdapAuthority("testRole", DN, attributes);
	}

	@Test
	public void testGetDn() {
		assertThat(authority.getDn()).isEqualTo(DN);
		assertThat(authority.getAttributeValues(SpringSecurityLdapTemplate.DN_KEY)).isNotNull();
		assertThat(authority.getAttributeValues(SpringSecurityLdapTemplate.DN_KEY)).hasSize(1);
		assertThat(authority.getFirstAttributeValue(SpringSecurityLdapTemplate.DN_KEY)).isEqualTo(DN);
	}

	@Test
	public void testGetAttributes() {
		assertThat(authority.getAttributes()).isNotNull();
		assertThat(authority.getAttributeValues("mail")).isNotNull();
		assertThat(authority.getAttributeValues("mail")).hasSize(2);
		assertThat(authority.getFirstAttributeValue("mail")).isEqualTo("filip@ldap.test.org");
		assertThat(authority.getAttributeValues("mail").get(0)).isEqualTo("filip@ldap.test.org");
		assertThat(authority.getAttributeValues("mail").get(1)).isEqualTo("filip@ldap.test2.org");
	}

	@Test
	public void testGetAuthority() {
		assertThat(authority.getAuthority()).isNotNull();
		assertThat(authority.getAuthority()).isEqualTo("testRole");
	}

}
