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

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Luke Taylor
 */
public class SimpleAuthoritiesMapperTests {

	@Test
	public void rejectsInvalidCaseConversionFlags() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setConvertToLowerCase(true);
		mapper.setConvertToUpperCase(true);
		assertThatIllegalArgumentException().isThrownBy(mapper::afterPropertiesSet);
	}

	@Test
	public void defaultPrefixIsCorrectlyApplied() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		Set<String> mapped = AuthorityUtils
			.authorityListToSet(mapper.mapAuthorities(AuthorityUtils.createAuthorityList("AaA", "ROLE_bbb")));
		assertThat(mapped).contains("ROLE_AaA");
		assertThat(mapped).contains("ROLE_bbb");
	}

	@Test
	public void caseIsConvertedCorrectly() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setPrefix("");
		List<GrantedAuthority> toMap = AuthorityUtils.createAuthorityList("AaA", "Bbb");
		Set<String> mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
		assertThat(mapped).hasSize(2);
		assertThat(mapped).contains("AaA");
		assertThat(mapped).contains("Bbb");
		mapper.setConvertToLowerCase(true);
		mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
		assertThat(mapped).hasSize(2);
		assertThat(mapped).contains("aaa");
		assertThat(mapped).contains("bbb");
		mapper.setConvertToLowerCase(false);
		mapper.setConvertToUpperCase(true);
		mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(toMap));
		assertThat(mapped).hasSize(2);
		assertThat(mapped).contains("AAA");
		assertThat(mapped).contains("BBB");
	}

	@Test
	public void duplicatesAreRemoved() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setConvertToUpperCase(true);
		Set<String> mapped = AuthorityUtils
			.authorityListToSet(mapper.mapAuthorities(AuthorityUtils.createAuthorityList("AaA", "AAA")));
		assertThat(mapped).hasSize(1);
	}

	@Test
	public void defaultAuthorityIsAssignedIfSet() {
		SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
		mapper.setDefaultAuthority("ROLE_USER");
		Set<String> mapped = AuthorityUtils.authorityListToSet(mapper.mapAuthorities(AuthorityUtils.NO_AUTHORITIES));
		assertThat(mapped).hasSize(1);
		assertThat(mapped).contains("ROLE_USER");
	}

}
