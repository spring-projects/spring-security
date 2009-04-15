package org.springframework.security.core.authority.mapping;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class SimpleRoles2GrantedAuthoritiesMapperTests extends TestCase {

    public final void testAfterPropertiesSetConvertToUpperAndLowerCase() {
        SimpleAttributes2GrantedAuthoritiesMapper mapper = new SimpleAttributes2GrantedAuthoritiesMapper();
        mapper.setConvertAttributeToLowerCase(true);
        mapper.setConvertAttributeToUpperCase(true);
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
        mapper.setConvertAttributeToUpperCase(true);
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    public final void testGetGrantedAuthoritiesToLowerCase() {
        String[] roles = { "Role1", "Role2" };
        String[] expectedGas = { "role1", "role2" };
        SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        mapper.setConvertAttributeToLowerCase(true);
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    public final void testGetGrantedAuthoritiesAddPrefixIfAlreadyExisting() {
        String[] roles = { "Role1", "Role2", "ROLE_Role3" };
        String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_ROLE_Role3" };
        SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        mapper.setAddPrefixIfAlreadyExisting(true);
        mapper.setAttributePrefix("ROLE_");
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    public final void testGetGrantedAuthoritiesDontAddPrefixIfAlreadyExisting1() {
        String[] roles = { "Role1", "Role2", "ROLE_Role3" };
        String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_Role3" };
        SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        mapper.setAddPrefixIfAlreadyExisting(false);
        mapper.setAttributePrefix("ROLE_");
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    public final void testGetGrantedAuthoritiesDontAddPrefixIfAlreadyExisting2() {
        String[] roles = { "Role1", "Role2", "role_Role3" };
        String[] expectedGas = { "ROLE_Role1", "ROLE_Role2", "ROLE_role_Role3" };
        SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        mapper.setAddPrefixIfAlreadyExisting(false);
        mapper.setAttributePrefix("ROLE_");
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    public final void testGetGrantedAuthoritiesCombination1() {
        String[] roles = { "Role1", "Role2", "role_Role3" };
        String[] expectedGas = { "ROLE_ROLE1", "ROLE_ROLE2", "ROLE_ROLE3" };
        SimpleAttributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        mapper.setAddPrefixIfAlreadyExisting(false);
        mapper.setConvertAttributeToUpperCase(true);
        mapper.setAttributePrefix("ROLE_");
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    private void testGetGrantedAuthorities(SimpleAttributes2GrantedAuthoritiesMapper mapper, String[] roles, String[] expectedGas) {
        List<GrantedAuthority> result = mapper.getGrantedAuthorities(Arrays.asList(roles));
        Collection<String> resultColl = new ArrayList<String>(result.size());
        for (int i = 0; i < result.size(); i++) {
            resultColl.add(result.get(i).getAuthority());
        }
        Collection<String> expectedColl = Arrays.asList(expectedGas);
        assertTrue("Role collections do not match; result: " + resultColl + ", expected: " + expectedColl, expectedColl
                .containsAll(resultColl)
                && resultColl.containsAll(expectedColl));
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
