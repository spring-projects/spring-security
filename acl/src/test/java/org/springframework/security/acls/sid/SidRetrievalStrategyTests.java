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
package org.springframework.security.acls.sid;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests for {@link SidRetrievalStrategyImpl}
 *
 * @author Andrei Stefan
 * @author Luke Taylor
 */
@SuppressWarnings("unchecked")
public class SidRetrievalStrategyTests {

	Authentication authentication = new TestingAuthenticationToken("scott", "password", "A", "B", "C");

	@Test
	public void correctSidsAreRetrieved() {
		SidRetrievalStrategy retrStrategy = new SidRetrievalStrategyImpl();
		List<Sid> sids = retrStrategy.getSids(authentication);

		assertThat(sids).isNotNull();
		assertThat(sids).hasSize(4);
		assertThat(sids.get(0)).isNotNull();
		assertThat(sids.get(0) instanceof PrincipalSid).isTrue();

		for (int i = 1; i < sids.size(); i++) {
			assertThat(sids.get(i) instanceof GrantedAuthoritySid).isTrue();
		}

		assertThat(((PrincipalSid) sids.get(0)).getPrincipal()).isEqualTo("scott");
		assertThat(((GrantedAuthoritySid) sids.get(1)).getGrantedAuthority()).isEqualTo("A");
		assertThat(((GrantedAuthoritySid) sids.get(2)).getGrantedAuthority()).isEqualTo("B");
		assertThat(((GrantedAuthoritySid) sids.get(3)).getGrantedAuthority()).isEqualTo("C");
	}

	@Test
	public void roleHierarchyIsUsedWhenSet() {
		RoleHierarchy rh = mock(RoleHierarchy.class);
		List rhAuthorities = AuthorityUtils.createAuthorityList("D");
		when(rh.getReachableGrantedAuthorities(anyCollection())).thenReturn(rhAuthorities);
		SidRetrievalStrategy strat = new SidRetrievalStrategyImpl(rh);

		List<Sid> sids = strat.getSids(authentication);
		assertThat(sids).hasSize(2);
		assertThat(sids.get(0)).isNotNull();
		assertThat(sids.get(0) instanceof PrincipalSid).isTrue();
		assertThat(((GrantedAuthoritySid) sids.get(1)).getGrantedAuthority()).isEqualTo("D");
	}

}
