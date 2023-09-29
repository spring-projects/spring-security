/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.core.authority;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 * @author Evgeniy Cheban
 */
public class AuthorityUtilsTests {

	@Test
	public void commaSeparatedStringIsParsedCorrectly() {
		List<GrantedAuthority> authorityArray = AuthorityUtils
			.commaSeparatedStringToAuthorityList(" ROLE_A, B, C, ROLE_D\n,\n E ");
		Set<String> authorities = AuthorityUtils.authorityListToSet(authorityArray);
		assertThat(authorities).contains("B");
		assertThat(authorities).contains("C");
		assertThat(authorities).contains("E");
		assertThat(authorities).contains("ROLE_A");
		assertThat(authorities).contains("ROLE_D");
	}

	@Test
	public void createAuthorityList() {
		List<GrantedAuthority> authorities = AuthorityUtils
			.createAuthorityList(Arrays.asList("ROLE_A", "ROLE_B", "ROLE_C"));
		assertThat(authorities).hasSize(3);
		assertThat(authorities).element(0).extracting(GrantedAuthority::getAuthority).isEqualTo("ROLE_A");
		assertThat(authorities).element(1).extracting(GrantedAuthority::getAuthority).isEqualTo("ROLE_B");
		assertThat(authorities).element(2).extracting(GrantedAuthority::getAuthority).isEqualTo("ROLE_C");
	}

}
