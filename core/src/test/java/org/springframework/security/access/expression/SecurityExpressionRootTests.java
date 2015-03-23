package org.springframework.security.access.expression;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.fest.assertions.Assertions.*;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityExpressionRootTests {
	final static Authentication JOE = new TestingAuthenticationToken("joe", "pass",
			"ROLE_A", "ROLE_B");

	SecurityExpressionRoot root;

	@Before
	public void setup() {
		root = new SecurityExpressionRoot(JOE) {
		};
	}

	@Test
	public void denyAllIsFalsePermitAllTrue() throws Exception {
		assertFalse(root.denyAll());
		assertFalse(root.denyAll);
		assertTrue(root.permitAll());
		assertTrue(root.permitAll);
	}

	@Test
	public void rememberMeIsCorrectlyDetected() throws Exception {
		AuthenticationTrustResolver atr = mock(AuthenticationTrustResolver.class);
		root.setTrustResolver(atr);
		when(atr.isRememberMe(JOE)).thenReturn(true);
		assertTrue(root.isRememberMe());
		assertFalse(root.isFullyAuthenticated());
	}

	@Test
	public void roleHierarchySupportIsCorrectlyUsedInEvaluatingRoles() throws Exception {
		root.setRoleHierarchy(new RoleHierarchy() {
			public Collection<GrantedAuthority> getReachableGrantedAuthorities(
					Collection<? extends GrantedAuthority> authorities) {
				return AuthorityUtils.createAuthorityList("ROLE_C");
			}
		});

		assertTrue(root.hasRole("C"));
		assertTrue(root.hasAuthority("ROLE_C"));
		assertFalse(root.hasRole("A"));
		assertFalse(root.hasRole("B"));
		assertTrue(root.hasAnyRole("C", "A", "B"));
		assertTrue(root.hasAnyAuthority("ROLE_C", "ROLE_A", "ROLE_B"));
		assertFalse(root.hasAnyRole("A", "B"));
	}

	@Test
	public void hasRoleAddsDefaultPrefix() throws Exception {
		assertThat(root.hasRole("A")).isTrue();
		assertThat(root.hasRole("NO")).isFalse();
	}

	@Test
	public void hasRoleEmptyPrefixDoesNotAddsDefaultPrefix() throws Exception {
		root.setDefaultRolePrefix("");
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasRoleNullPrefixDoesNotAddsDefaultPrefix() throws Exception {
		root.setDefaultRolePrefix(null);
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasRoleDoesNotAddDefaultPrefixForAlreadyPrefixedRoles() throws Exception {
		SecurityExpressionRoot root = new SecurityExpressionRoot(JOE) {
		};

		assertThat(root.hasRole("ROLE_A")).isTrue();
		assertThat(root.hasRole("ROLE_NO")).isFalse();
	}

	@Test
	public void hasAnyRoleAddsDefaultPrefix() throws Exception {
		assertThat(root.hasAnyRole("NO", "A")).isTrue();
		assertThat(root.hasAnyRole("NO", "NOT")).isFalse();
	}

	@Test
	public void hasAnyRoleDoesNotAddDefaultPrefixForAlreadyPrefixedRoles()
			throws Exception {
		assertThat(root.hasAnyRole("ROLE_NO", "ROLE_A")).isTrue();
		assertThat(root.hasAnyRole("ROLE_NO", "ROLE_NOT")).isFalse();
	}

	@Test
	public void hasAnyRoleEmptyPrefixDoesNotAddsDefaultPrefix() throws Exception {
		root.setDefaultRolePrefix("");
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasAnyRoleNullPrefixDoesNotAddsDefaultPrefix() throws Exception {
		root.setDefaultRolePrefix(null);
		assertThat(root.hasAnyRole("A")).isFalse();
		assertThat(root.hasAnyRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasAuthorityDoesNotAddDefaultPrefix() throws Exception {
		assertThat(root.hasAuthority("A")).isFalse();
		assertThat(root.hasAnyAuthority("NO", "A")).isFalse();
		assertThat(root.hasAnyAuthority("ROLE_A", "NOT")).isTrue();
	}
}
