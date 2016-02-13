package org.springframework.security.core.authority;

import static org.assertj.core.api.Assertions.*;

import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author Luke Taylor
 */
public class AuthorityUtilsTests {

	@Test
	public void commaSeparatedStringIsParsedCorrectly() {
		List<GrantedAuthority> authorityArray = AuthorityUtils
				.commaSeparatedStringToAuthorityList(" ROLE_A, B, C, ROLE_D\n,\n E ");

		Set<String> authorities = AuthorityUtils.authorityListToSet(authorityArray);

		assertThat(authorities.contains("B")).isTrue();
		assertThat(authorities.contains("C")).isTrue();
		assertThat(authorities.contains("E")).isTrue();
		assertThat(authorities.contains("ROLE_A")).isTrue();
		assertThat(authorities.contains("ROLE_D")).isTrue();
	}
}
