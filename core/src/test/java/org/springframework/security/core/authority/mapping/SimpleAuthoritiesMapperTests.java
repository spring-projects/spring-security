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
		Set<String> mapped = AuthorityUtils.authorityListToSet(mapper
				.mapAuthorities(AuthorityUtils.createAuthorityList("AaA", "ROLE_bbb")));
		assertThat(mapped.contains("ROLE_AaA")).isTrue();
		assertThat(mapped.contains("ROLE_bbb")).isTrue();
	}

	@Test
	public void caseIsConvertedCorrectly() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setPrefix("");
		List<GrantedAuthority> toMap = AuthorityUtils.createAuthorityList("AaA", "Bbb");
		Set<String> mapped = AuthorityUtils.authorityListToSet(mapper
				.mapAuthorities(toMap));
		assertThat(mapped).hasSize(2);
		assertThat(mapped.contains("AaA")).isTrue();
		assertThat(mapped.contains("Bbb")).isTrue();

		mapper.setConvertToLowerCase(true);
		mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
		assertThat(mapped).hasSize(2);
		assertThat(mapped.contains("aaa")).isTrue();
		assertThat(mapped.contains("bbb")).isTrue();

		mapper.setConvertToLowerCase(false);
		mapper.setConvertToUpperCase(true);
		mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
		assertThat(mapped).hasSize(2);
		assertThat(mapped.contains("AAA")).isTrue();
		assertThat(mapped.contains("BBB")).isTrue();
	}

	@Test
	public void duplicatesAreRemoved() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setConvertToUpperCase(true);

		Set<String> mapped = AuthorityUtils.authorityListToSet(mapper
				.mapAuthorities(AuthorityUtils.createAuthorityList("AaA", "AAA")));
		assertThat(mapped).hasSize(1);
	}

	@Test
	public void defaultAuthorityIsAssignedIfSet() throws Exception {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setDefaultAuthority("ROLE_USER");
		Set<String> mapped = AuthorityUtils.authorityListToSet(mapper
				.mapAuthorities(AuthorityUtils.NO_AUTHORITIES));
		assertThat(mapped).hasSize(1);
		assertThat(mapped.contains("ROLE_USER")).isTrue();
	}
}
