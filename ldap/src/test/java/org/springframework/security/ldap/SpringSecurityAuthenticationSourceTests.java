package org.springframework.security.ldap;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.authentication.SpringSecurityAuthenticationSource;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.DistinguishedName;

import org.junit.After;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class SpringSecurityAuthenticationSourceTests {
	@Before
	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void principalAndCredentialsAreEmptyWithNoAuthentication() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		assertThat(source.getPrincipal()).isEqualTo("");
		assertThat(source.getCredentials()).isEqualTo("");
	}

	@Test
	public void principalIsEmptyForAnonymousUser() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();

		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("key", "anonUser", AuthorityUtils
						.createAuthorityList("ignored")));
		assertThat(source.getPrincipal()).isEqualTo("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void getPrincipalRejectsNonLdapUserDetailsObject() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken(new Object(), "password"));

		source.getPrincipal();
	}

	@Test
	public void expectedCredentialsAreReturned() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken(new Object(), "password"));

		assertThat(source.getCredentials()).isEqualTo("password");
	}

	@Test
	public void expectedPrincipalIsReturned() {
		LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
		user.setUsername("joe");
		user.setDn(new DistinguishedName("uid=joe,ou=users"));
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken(user.createUserDetails(), null));

		assertThat(source.getPrincipal()).isEqualTo("uid=joe,ou=users");
	}
}
