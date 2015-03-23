package org.springframework.security.ldap.userdetails;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
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
		assertEquals(DN, authority.getDn());
		assertNotNull(authority.getAttributeValues(SpringSecurityLdapTemplate.DN_KEY));
		assertEquals(1, authority.getAttributeValues(SpringSecurityLdapTemplate.DN_KEY)
				.size());
		assertEquals(DN,
				authority.getFirstAttributeValue(SpringSecurityLdapTemplate.DN_KEY));
	}

	@Test
	public void testGetAttributes() throws Exception {
		assertNotNull(authority.getAttributes());
		assertNotNull(authority.getAttributeValues("mail"));
		assertEquals(2, authority.getAttributeValues("mail").size());
		assertEquals("filip@ldap.test.org", authority.getFirstAttributeValue("mail"));
		assertEquals("filip@ldap.test.org", authority.getAttributeValues("mail").get(0));
		assertEquals("filip@ldap.test2.org", authority.getAttributeValues("mail").get(1));
	}

	@Test
	public void testGetAuthority() throws Exception {
		assertNotNull(authority.getAuthority());
		assertEquals("testRole", authority.getAuthority());
	}
}