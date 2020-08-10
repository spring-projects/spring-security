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
package org.springframework.security.core.authority.mapping;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * @author TSARDD
 * @since 18-okt-2007
 */
public class SimpleRoles2GrantedAuthoritiesMapperTests {

	@Test
	public final void testAfterPropertiesSetConvertToUpperAndLowerCase() {
		SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
		mapper.setConvertAttributeToLowerCase(true);
		mapper.setConvertAttributeToUpperCase(true);
		try {
			mapper.afterPropertiesSet();
			fail("Expected exception not thrown");
		}
		catch (IllegalArgumentException expected) {
		}
		catch (Exception unexpected) {
			fail("Unexpected exception: " + unexpected);
		}
	}

	@Test
	public final void testAfterPropertiesSet() {
		SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
		try {
			mapper.afterPropertiesSet();
		}
		catch (Exception unexpected) {
			fail("Unexpected exception: " + unexpected);
		}
	}

	@Test
	public final void testGetGrantedAuthoritiesNoConversion() {
		String[] roles = { "Role1", "Role2" };
		String[] expectedGas = { "Role1", "Role2" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	@Test
	public final void testGetGrantedAuthoritiesToUpperCase() {
		String[] roles = { "Role1", "Role2" };
		String[] expectedGas = { "ROLE1", "ROLE2" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setConvertAttributeToUpperCase(true);
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	@Test
	public final void testGetGrantedAuthoritiesToLowerCase() {
		String[] roles = { "Role1", "Role2" };
		String[] expectedGas = { "role1", "role2" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setConvertAttributeToLowerCase(true);
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	@Test
	public final void testGetGrantedAuthoritiesAddPrefixIfAlreadyExisting() {
		String[] roles = { "Role1", "Role2", "ROLE_Role3" };
		String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_ROLE_Role3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(true);
		mapper.setAttributePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	@Test
	public final void testGetGrantedAuthoritiesDontAddPrefixIfAlreadyExisting1() {
		String[] roles = { "Role1", "Role2", "ROLE_Role3" };
		String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_Role3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(false);
		mapper.setAttributePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	@Test
	public final void testGetGrantedAuthoritiesDontAddPrefixIfAlreadyExisting2() {
		String[] roles = { "Role1", "Role2", "role_Role3" };
		String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_role_Role3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(false);
		mapper.setAttributePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	@Test
	public final void testGetGrantedAuthoritiesCombination1() {
		String[] roles = { "Role1", "Role2", "role_Role3" };
		String[] expectedGas = { "ROLE_ROLE1", "ROLE_ROLE2", "ROLE_ROLE3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(false);
		mapper.setConvertAttributeToUpperCase(true);
		mapper.setAttributePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	private void testGetGrantedAuthorities(SimpleAttributes2GrantedAuthoritiesMapper mapper, String[] roles,
			String[] expectedGas) {
		List<GrantedAuthority> result = mapper.getGrantedAuthorities(Arrays.asList(roles));
		Collection<String> resultColl = new ArrayList<>(result.size());
		for (GrantedAuthority grantedAuthority : result) {
			resultColl.add(grantedAuthority.getAuthority());
		}
		Collection<String> expectedColl = Arrays.asList(expectedGas);
		assertThat(expectedColl.containsAll(resultColl) && resultColl.containsAll(expectedColl))
				.withFailMessage("Role collections do not match; result: " + resultColl + ", expected: " + expectedColl)
				.isTrue();
	}

	private SimpleAttributes2GrantedAuthoritiesMapper getDefaultMapper() {
		SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
		mapper.setAttributePrefix("");
		mapper.setConvertAttributeToLowerCase(false);
		mapper.setConvertAttributeToUpperCase(false);
		mapper.setAddPrefixIfAlreadyExisting(false);
		return mapper;
	}

}
