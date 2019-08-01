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

package org.springframework.security.core.userdetails.jdbc;

import org.junit.Test;

import org.springframework.context.MessageSource;
import org.springframework.security.PopulatedDatabase;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link JdbcDaoImpl}.
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 */
public class JdbcDaoImplTests {

	// ~ Methods
	// ========================================================================================================

	private JdbcDaoImpl makePopulatedJdbcDao() throws Exception {
		JdbcDaoImpl dao = new JdbcDaoImpl();
		dao.setDataSource(PopulatedDatabase.getDataSource());
		dao.afterPropertiesSet();

		return dao;
	}

	private JdbcDaoImpl makePopulatedJdbcDaoWithRolePrefix() throws Exception {
		JdbcDaoImpl dao = new JdbcDaoImpl();
		dao.setDataSource(PopulatedDatabase.getDataSource());
		dao.setRolePrefix("ARBITRARY_PREFIX_");
		dao.afterPropertiesSet();

		return dao;
	}

	@Test
	public void testCheckDaoAccessUserSuccess() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();
		UserDetails user = dao.loadUserByUsername("rod");
		assertThat(user.getUsername()).isEqualTo("rod");
		assertThat(user.getPassword()).isEqualTo("koala");
		assertThat(user.isEnabled()).isTrue();

		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities()))
				.contains("ROLE_TELLER");
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities()))
				.contains("ROLE_SUPERVISOR");
	}

	@Test
	public void testCheckDaoOnlyReturnsGrantedAuthoritiesGrantedToUser()
			throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();
		UserDetails user = dao.loadUserByUsername("scott");
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities()))
				.contains("ROLE_TELLER");
	}

	@Test
	public void testCheckDaoReturnsCorrectDisabledProperty() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();
		UserDetails user = dao.loadUserByUsername("peter");
		assertThat(user.isEnabled()).isFalse();
	}

	@Test
	public void testGettersSetters() {
		JdbcDaoImpl dao = new JdbcDaoImpl();
		dao.setAuthoritiesByUsernameQuery("SELECT * FROM FOO");
		assertThat(dao.getAuthoritiesByUsernameQuery()).isEqualTo("SELECT * FROM FOO");

		dao.setUsersByUsernameQuery("SELECT USERS FROM FOO");
		assertThat(dao.getUsersByUsernameQuery()).isEqualTo("SELECT USERS FROM FOO");
	}

	@Test
	public void testLookupFailsIfUserHasNoGrantedAuthorities() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();

		try {
			dao.loadUserByUsername("cooper");
			fail("Should have thrown UsernameNotFoundException");
		}
		catch (UsernameNotFoundException expected) {
		}
	}

	@Test
	public void testLookupFailsWithWrongUsername() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();

		try {
			dao.loadUserByUsername("UNKNOWN_USER");
			fail("Should have thrown UsernameNotFoundException");
		}
		catch (UsernameNotFoundException expected) {

		}
	}

	@Test
	public void testLookupSuccessWithMixedCase() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();
		assertThat(dao.loadUserByUsername("rod").getPassword()).isEqualTo("koala");
		assertThat(dao.loadUserByUsername("ScOTt").getPassword()).isEqualTo("wombat");
	}

	@Test
	public void testRolePrefixWorks() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDaoWithRolePrefix();
		assertThat(dao.getRolePrefix()).isEqualTo("ARBITRARY_PREFIX_");

		UserDetails user = dao.loadUserByUsername("rod");
		assertThat(user.getUsername()).isEqualTo("rod");
		assertThat(user.getAuthorities()).hasSize(2);

		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities()))
				.contains("ARBITRARY_PREFIX_ROLE_TELLER");
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities()))
				.contains("ARBITRARY_PREFIX_ROLE_SUPERVISOR");
	}

	@Test
	public void testGroupAuthoritiesAreLoadedCorrectly() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();
		dao.setEnableAuthorities(false);
		dao.setEnableGroups(true);

		UserDetails jerry = dao.loadUserByUsername("jerry");
		assertThat(jerry.getAuthorities()).hasSize(3);
	}

	@Test
	public void testDuplicateGroupAuthoritiesAreRemoved() throws Exception {
		JdbcDaoImpl dao = makePopulatedJdbcDao();
		dao.setEnableAuthorities(false);
		dao.setEnableGroups(true);
		// Tom has roles A, B, C and B, C duplicates
		UserDetails tom = dao.loadUserByUsername("tom");
		assertThat(tom.getAuthorities()).hasSize(3);
	}

	@Test
	public void testStartupFailsIfDataSourceNotSet() throws Exception {
		JdbcDaoImpl dao = new JdbcDaoImpl();

		try {
			dao.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testStartupFailsIfUserMapSetToNull() throws Exception {
		JdbcDaoImpl dao = new JdbcDaoImpl();

		try {
			dao.setDataSource(null);
			dao.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void setMessageSourceWhenNullThenThrowsException() throws Exception {
		JdbcDaoImpl dao = new JdbcDaoImpl();

		dao.setMessageSource(null);
	}

	@Test
	public void setMessageSourceWhenNotNullThenCanGet() throws Exception {
		MessageSource source = mock(MessageSource.class);
		JdbcDaoImpl dao = new JdbcDaoImpl();
		dao.setMessageSource(source);
		String code = "code";

		dao.getMessages().getMessage(code);

		verify(source).getMessage(eq(code), any(), any());
	}
}
