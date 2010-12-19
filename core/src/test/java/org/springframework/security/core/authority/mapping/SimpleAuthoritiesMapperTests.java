package org.springframework.security.core.authority.mapping;


import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class SimpleAuthoritiesMapperTests {

    @Test(expected = IllegalArgumentException.class)
    public void rejectsInvalidCaseConversionFlags() throws Exception {
        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        mapper.setConvertToLowerCase(true);
        mapper.setConvertToUpperCase(true);
        mapper.afterPropertiesSet();
    }

    @Test
    public void defaultPrefixIsCorrectlyApplied() {
        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        Set<String> mapped = AuthorityUtils.authorityListToSet(
                mapper.mapAuthorities(AuthorityUtils.createAuthorityList("AaA", "ROLE_bbb")));
        assertTrue(mapped.contains("ROLE_AaA"));
        assertTrue(mapped.contains("ROLE_bbb"));
    }

    @Test
    public void caseIsConvertedCorrectly() {
        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        mapper.setPrefix("");
        List<GrantedAuthority> toMap = AuthorityUtils.createAuthorityList("AaA", "Bbb");
        Set<String> mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
        assertEquals(2, mapped.size());
        assertTrue(mapped.contains("AaA"));
        assertTrue(mapped.contains("Bbb"));

        mapper.setConvertToLowerCase(true);
        mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
        assertEquals(2, mapped.size());
        assertTrue(mapped.contains("aaa"));
        assertTrue(mapped.contains("bbb"));

        mapper.setConvertToLowerCase(false);
        mapper.setConvertToUpperCase(true);
        mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
        assertEquals(2, mapped.size());
        assertTrue(mapped.contains("AAA"));
        assertTrue(mapped.contains("BBB"));
    }

    @Test
    public void duplicatesAreRemoved() {
        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        mapper.setConvertToUpperCase(true);

        Set<String> mapped = AuthorityUtils.authorityListToSet(
                mapper.mapAuthorities(AuthorityUtils.createAuthorityList("AaA", "AAA")));
        assertEquals(1, mapped.size());
    }

    @Test
    public void defaultAuthorityIsAssignedIfSet() throws Exception {
        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        mapper.setDefaultAuthority("ROLE_USER");
        Set<String> mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(AuthorityUtils.NO_AUTHORITIES));
        assertEquals(1, mapped.size());
        assertTrue(mapped.contains("ROLE_USER"));
    }
}
