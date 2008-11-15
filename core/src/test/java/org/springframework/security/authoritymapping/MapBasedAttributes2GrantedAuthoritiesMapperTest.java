package org.springframework.security.authoritymapping;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

/**
 *
 * @author Ruud Senden
 */
@SuppressWarnings("unchecked")
public class MapBasedAttributes2GrantedAuthoritiesMapperTest {

    protected void setUp() throws Exception {
        // Set Log4j loglevel to debug to include all logstatements in tests
        Logger.getRootLogger().setLevel(Level.DEBUG);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testAfterPropertiesSetNoMap() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        mapper.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testAfterPropertiesSetEmptyMap() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        mapper.setAttributes2grantedAuthoritiesMap(new HashMap());
        mapper.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testAfterPropertiesSetInvalidKeyTypeMap() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        HashMap m = new HashMap();
        m.put(new Object(),"ga1");
        mapper.setAttributes2grantedAuthoritiesMap(m);
        mapper.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testAfterPropertiesSetInvalidValueTypeMap1() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        HashMap m = new HashMap();
        m.put("role1",new Object());
        mapper.setAttributes2grantedAuthoritiesMap(m);
        mapper.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testAfterPropertiesSetInvalidValueTypeMap2() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        HashMap m = new HashMap();
        m.put("role1",new Object[]{new String[]{"ga1","ga2"}, new Object()});
        mapper.setAttributes2grantedAuthoritiesMap(m);
        mapper.afterPropertiesSet();
    }

    @Test
    public void testAfterPropertiesSetValidMap() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        HashMap m = getValidAttributes2GrantedAuthoritiesMap();
        mapper.setAttributes2grantedAuthoritiesMap(m);
        mapper.afterPropertiesSet();
    }

    @Test
    public void testMapping1() throws Exception {
        String[] roles = { "role1" };
        String[] expectedGas = { "ga1" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping2() throws Exception {
        String[] roles = { "role2" };
        String[] expectedGas = { "ga2" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping3() throws Exception {
        String[] roles = { "role3" };
        String[] expectedGas = { "ga3", "ga4" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping4() throws Exception {
        String[] roles = { "role4" };
        String[] expectedGas = { "ga5", "ga6" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping5() throws Exception {
        String[] roles = { "role5" };
        String[] expectedGas = { "ga7", "ga8", "ga9" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping6() throws Exception {
        String[] roles = { "role6" };
        String[] expectedGas = { "ga10", "ga11", "ga12" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping7() throws Exception {
        String[] roles = { "role7" };
        String[] expectedGas = { "ga13", "ga14" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping8() throws Exception {
        String[] roles = { "role8" };
        String[] expectedGas = { "ga13", "ga14" };
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping9() throws Exception {
        String[] roles = { "role9" };
        String[] expectedGas = {};
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping10() throws Exception {
        String[] roles = { "role10" };
        String[] expectedGas = {};
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMapping11() throws Exception {
        String[] roles = { "role11" };
        String[] expectedGas = {};
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testNonExistingMapping() throws Exception {
        String[] roles = { "nonExisting" };
        String[] expectedGas = {};
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    @Test
    public void testMappingCombination() throws Exception {
        String[] roles = { "role1", "role2", "role3", "role4", "role5", "role6", "role7", "role8", "role9", "role10", "role11" };
        String[] expectedGas = { "ga1", "ga2", "ga3", "ga4", "ga5", "ga6", "ga7", "ga8", "ga9", "ga10", "ga11", "ga12", "ga13", "ga14"};
        Attributes2GrantedAuthoritiesMapper mapper = getDefaultMapper();
        testGetGrantedAuthorities(mapper, roles, expectedGas);
    }

    private HashMap getValidAttributes2GrantedAuthoritiesMap() {
        HashMap m = new HashMap();
        m.put("role1","ga1");
        m.put("role2",new GrantedAuthorityImpl("ga2"));
        m.put("role3",Arrays.asList(new Object[]{"ga3",new GrantedAuthorityImpl("ga4")}));
        m.put("role4","ga5,ga6");
        m.put("role5",Arrays.asList(new Object[]{"ga7","ga8",new Object[]{new GrantedAuthorityImpl("ga9")}}));
        m.put("role6",new Object[]{"ga10","ga11",new Object[]{new GrantedAuthorityImpl("ga12")}});
        m.put("role7",new String[]{"ga13","ga14"});
        m.put("role8",new String[]{"ga13","ga14",null});
        m.put("role9",null);
        m.put("role10",new Object[]{});
        m.put("role11",Arrays.asList(new Object[]{null}));
        return m;
    }

    private MapBasedAttributes2GrantedAuthoritiesMapper getDefaultMapper() throws Exception {
        MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
        mapper.setAttributes2grantedAuthoritiesMap(getValidAttributes2GrantedAuthoritiesMap());
        mapper.afterPropertiesSet();
        return mapper;
    }

    private void testGetGrantedAuthorities(Attributes2GrantedAuthoritiesMapper mapper, String[] roles, String[] expectedGas) {
        List<GrantedAuthority> result = mapper.getGrantedAuthorities(Arrays.asList(roles));
        Collection resultColl = new ArrayList(result.size());
        for (int i = 0; i < result.size(); i++) {
            resultColl.add(result.get(i).getAuthority());
        }
        Collection expectedColl = Arrays.asList(expectedGas);
        assertTrue("Role collections should match; result: " + resultColl + ", expected: " + expectedColl, expectedColl
                .containsAll(resultColl)
                && resultColl.containsAll(expectedColl));
    }
}
