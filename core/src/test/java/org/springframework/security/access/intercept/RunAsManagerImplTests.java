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

package org.springframework.security.access.intercept;

import java.util.Set;

import org.junit.Test;

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 */
public class RunAsManagerImplTests {

	@Test
	public void testAlwaysSupportsClass() {
		RunAsManagerImpl runAs = new RunAsManagerImpl();
		assertThat(runAs.supports(String.class)).isTrue();
	}

	@Test
	public void testDoesNotReturnAdditionalAuthoritiesIfCalledWithoutARunAsSetting() {
		UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));

		RunAsManagerImpl runAs = new RunAsManagerImpl();
		runAs.setKey("my_password");

		Authentication resultingToken = runAs.buildRunAs(inputToken, new Object(),
				SecurityConfig.createList("SOMETHING_WE_IGNORE"));
		assertThat(resultingToken).isNull();
	}

	@Test
	public void testRespectsRolePrefix() {
		UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test", "Password",
				AuthorityUtils.createAuthorityList("ONE", "TWO"));

		RunAsManagerImpl runAs = new RunAsManagerImpl();
		runAs.setKey("my_password");
		runAs.setRolePrefix("FOOBAR_");

		Authentication result = runAs.buildRunAs(inputToken, new Object(),
				SecurityConfig.createList("RUN_AS_SOMETHING"));

		assertThat(result instanceof RunAsUserToken).withFailMessage("Should have returned a RunAsUserToken").isTrue();
		assertThat(result.getPrincipal()).isEqualTo(inputToken.getPrincipal());
		assertThat(result.getCredentials()).isEqualTo(inputToken.getCredentials());
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());

		assertThat(authorities.contains("FOOBAR_RUN_AS_SOMETHING")).isTrue();
		assertThat(authorities.contains("ONE")).isTrue();
		assertThat(authorities.contains("TWO")).isTrue();

		RunAsUserToken resultCast = (RunAsUserToken) result;
		assertThat(resultCast.getKeyHash()).isEqualTo("my_password".hashCode());
	}

	@Test
	public void testReturnsAdditionalGrantedAuthorities() {
		UsernamePasswordAuthenticationToken inputToken = new UsernamePasswordAuthenticationToken("Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));

		RunAsManagerImpl runAs = new RunAsManagerImpl();
		runAs.setKey("my_password");

		Authentication result = runAs.buildRunAs(inputToken, new Object(),
				SecurityConfig.createList("RUN_AS_SOMETHING"));

		if (!(result instanceof RunAsUserToken)) {
			fail("Should have returned a RunAsUserToken");
		}

		assertThat(result.getPrincipal()).isEqualTo(inputToken.getPrincipal());
		assertThat(result.getCredentials()).isEqualTo(inputToken.getCredentials());

		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(authorities.contains("ROLE_RUN_AS_SOMETHING")).isTrue();
		assertThat(authorities.contains("ROLE_ONE")).isTrue();
		assertThat(authorities.contains("ROLE_TWO")).isTrue();

		RunAsUserToken resultCast = (RunAsUserToken) result;
		assertThat(resultCast.getKeyHash()).isEqualTo("my_password".hashCode());
	}

	@Test
	public void testStartupDetectsMissingKey() throws Exception {
		RunAsManagerImpl runAs = new RunAsManagerImpl();

		try {
			runAs.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testStartupSuccessfulWithKey() throws Exception {
		RunAsManagerImpl runAs = new RunAsManagerImpl();
		runAs.setKey("hello_world");
		runAs.afterPropertiesSet();
		assertThat(runAs.getKey()).isEqualTo("hello_world");
	}

	@Test
	public void testSupports() {
		RunAsManager runAs = new RunAsManagerImpl();
		assertThat(runAs.supports(new SecurityConfig("RUN_AS_SOMETHING"))).isTrue();
		assertThat(!runAs.supports(new SecurityConfig("ROLE_WHICH_IS_IGNORED"))).isTrue();
		assertThat(!runAs.supports(new SecurityConfig("role_LOWER_CASE_FAILS"))).isTrue();
	}

}
