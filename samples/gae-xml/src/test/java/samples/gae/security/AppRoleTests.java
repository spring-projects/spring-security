package samples.gae.security;

import static org.assertj.core.api.Assertions.*;
import static samples.gae.security.AppRole.*;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Luke Taylor
 */
public class AppRoleTests {

	@Test
	public void getAuthorityReturnsRoleName() {
		GrantedAuthority admin = ADMIN;

		assertThat(admin.getAuthority()).isEqualTo("ROLE_ADMIN");
	}

	@Test
	public void bitsAreCorrect() throws Exception {
		// If this fails, someone has modified the Enum and the Datastore is probably
		// corrupt!
		assertThat(ADMIN.getBit()).isEqualTo(0);
		assertThat(NEW_USER.getBit()).isEqualTo(1);
		assertThat(USER.getBit()).isEqualTo(2);
	}
}
