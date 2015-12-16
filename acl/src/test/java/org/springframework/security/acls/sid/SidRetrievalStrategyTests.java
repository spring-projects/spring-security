package org.springframework.security.acls.sid;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.util.Collection;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests for {@link SidRetrievalStrategyImpl}
 *
 * @author Andrei Stefan
 * @author Luke Taylor
 */
@SuppressWarnings("unchecked")
public class SidRetrievalStrategyTests {
	Authentication authentication = new TestingAuthenticationToken("scott", "password",
			"A", "B", "C");

	// ~ Methods
	// ========================================================================================================

	@Test
	public void correctSidsAreRetrieved() throws Exception {
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
	public void roleHierarchyIsUsedWhenSet() throws Exception {
		RoleHierarchy rh = mock(RoleHierarchy.class);
		List rhAuthorities = AuthorityUtils.createAuthorityList("D");
		when(rh.getReachableGrantedAuthorities(anyCollection()))
				.thenReturn(rhAuthorities);
		SidRetrievalStrategy strat = new SidRetrievalStrategyImpl(rh);

		List<Sid> sids = strat.getSids(authentication);
		assertThat(sids).hasSize(2);
		assertThat(sids.get(0)).isNotNull();
		assertThat(sids.get(0) instanceof PrincipalSid).isTrue();
		assertThat(((GrantedAuthoritySid) sids.get(1)).getGrantedAuthority()).isEqualTo("D");
	}
}
