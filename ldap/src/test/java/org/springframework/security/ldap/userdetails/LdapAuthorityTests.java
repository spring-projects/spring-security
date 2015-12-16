package org.springframework.security.ldap.userdetails;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertNotNull;

/**
 * @author Filip Hanik
 */
public class LdapAuthorityTests {

	public static final String DN = "cn=filip,ou=Users,dc=test,dc=com";
	LdapAuthority authority;

	@Before
	public void setUp() {
		Map<String, List<String>> attributes = new HashMap<String, List<String>>();
		attributes.put(SpringSecurityLdapTemplate.DN_KEY, Arrays.asList(DN));
		attributes.put("mail",
				Arrays.asList("filip@ldap.test.org", "filip@ldap.test2.org"));
		authority = new LdapAuthority("testRole", DN, attributes);
	}

	@Test
	public void testGetDn() throws Exception {
		assertThat(authority.getDn()).isEqualTo(DN);
		assertThat(authority.getAttributeValues(SpringSecurityLdapTemplate.DN_KEY)).isNotNull();
		assertThat(authority.getAttributeValues(SpringSecurityLdapTemplate.DN_KEY).isEqualTo(1)
				.size());
		assertEquals(DN,
				authority.getFirstAttributeValue(SpringSecurityLdapTemplate.DN_KEY));
	}

	@Test
	public void testGetAttributes() throws Exception {
		assertThat(authority.getAttributes()).isNotNull();
		assertThat(authority.getAttributeValues("mail")).isNotNull();
		assertThat(authority.getAttributeValues("mail")).hasSize(2);
		assertThat(authority.getFirstAttributeValue("mail")).isEqualTo("filip@ldap.test.org");
		assertThat(authority.getAttributeValues("mail").get(0)).isEqualTo("filip@ldap.test.org");
		assertThat(authority.getAttributeValues("mail").get(1)).isEqualTo("filip@ldap.test2.org");
	}

	@Test
	public void testGetAuthority() throws Exception {
		assertThat(authority.getAuthority()).isNotNull();
		assertThat(authority.getAuthority()).isEqualTo("testRole");
	}
}
