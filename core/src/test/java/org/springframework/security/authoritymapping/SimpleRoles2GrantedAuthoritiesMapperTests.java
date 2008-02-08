package org.springframework.security.authoritymapping;

import org.springframework.security.GrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import junit.framework.TestCase;

/**
 * 
 * @author TSARDD
 * @since 18-okt-2007
 */
public class SimpleRoles2GrantedAuthoritiesMapperTests extends TestCase {

	public final void testAfterPropertiesSetConvertToUpperAndLowerCase() {
		SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
		mapper.setConvertRoleToLowerCase(true);
		mapper.setConvertRoleToUpperCase(true);
		try {
			mapper.afterPropertiesSet();
			fail("Expected exception not thrown");
		} catch (IllegalArgumentException expected) {
		} catch (Exception unexpected) {
			fail("Unexpected exception: " + unexpected);
		}
	}

	public final void testAfterPropertiesSet() {
		SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
		try {
			mapper.afterPropertiesSet();
		} catch (Exception unexpected) {
			fail("Unexpected exception: " + unexpected);
		}
	}

	public final void testGetGrantedAuthoritiesNoConversion() {
		String[] roles = { "Role1", "Role2" };
		String[] expectedGas = { "Role1", "Role2" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	public final void testGetGrantedAuthoritiesToUpperCase() {
		String[] roles = { "Role1", "Role2" };
		String[] expectedGas = { "ROLE1", "ROLE2" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setConvertRoleToUpperCase(true);
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	public final void testGetGrantedAuthoritiesToLowerCase() {
		String[] roles = { "Role1", "Role2" };
		String[] expectedGas = { "role1", "role2" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setConvertRoleToLowerCase(true);
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	public final void testGetGrantedAuthoritiesAddPrefixIfAlreadyExisting() {
		String[] roles = { "Role1", "Role2", "ROLE_Role3" };
		String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_ROLE_Role3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(true);
		mapper.setRolePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	public final void testGetGrantedAuthoritiesDontAddPrefixIfAlreadyExisting1() {
		String[] roles = { "Role1", "Role2", "ROLE_Role3" };
		String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_Role3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(false);
		mapper.setRolePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	public final void testGetGrantedAuthoritiesDontAddPrefixIfAlreadyExisting2() {
		String[] roles = { "Role1", "Role2", "role_Role3" };
		String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_role_Role3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(false);
		mapper.setRolePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	public final void testGetGrantedAuthoritiesCombination1() {
		String[] roles = { "Role1", "Role2", "role_Role3" };
		String[] expectedGas = { "ROLE_ROLE1", "ROLE_ROLE2", "ROLE_ROLE3" };
		SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
		mapper.setAddPrefixIfAlreadyExisting(false);
		mapper.setConvertRoleToUpperCase(true);
		mapper.setRolePrefix("ROLE_");
		testGetGrantedAuthorities(mapper, roles, expectedGas);
	}

	private void testGetGrantedAuthorities(SimpleAttributes2GrantedAuthoritiesMapper mapper, String[] roles, String[] expectedGas) {
		GrantedAuthority[] result = mapper.getGrantedAuthorities(roles);
		Collection resultColl = new ArrayList(result.length);
		for (int i = 0; i < result.length; i++) {
			resultColl.add(result[i].getAuthority());
		}
		Collection expectedColl = Arrays.asList(expectedGas);
		assertTrue("Role collections do not match; result: " + resultColl + ", expected: " + expectedColl, expectedColl
				.containsAll(resultColl)
				&& resultColl.containsAll(expectedColl));
	}

	private SimpleAttributes2GrantedAuthoritiesMapper getDefaultMapper() {
		SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
		mapper.setRolePrefix("");
		mapper.setConvertRoleToLowerCase(false);
		mapper.setConvertRoleToUpperCase(false);
		mapper.setAddPrefixIfAlreadyExisting(false);
		return mapper;
	}

}
