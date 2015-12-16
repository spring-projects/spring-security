package samples.gae.users;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumSet;
import java.util.Set;

import com.google.appengine.tools.development.testing.LocalDatastoreServiceTestConfig;
import com.google.appengine.tools.development.testing.LocalServiceTestHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import samples.gae.security.AppRole;

/**
 * @author Luke Taylor
 */
public class GaeDataStoreUserRegistryTests {
	private final LocalServiceTestHelper helper = new LocalServiceTestHelper(
			new LocalDatastoreServiceTestConfig());

	@Before
	public void setUp() throws Exception {
		helper.setUp();
	}

	@After
	public void tearDown() throws Exception {
		helper.tearDown();
	}

	@Test
	public void correctDataIsRetrievedAfterInsert() {
		GaeDatastoreUserRegistry registry = new GaeDatastoreUserRegistry();

		Set<AppRole> roles = EnumSet.of(AppRole.ADMIN, AppRole.USER);
		String userId = "someUserId";

		GaeUser origUser = new GaeUser(userId, "nick", "nick@blah.com", "Forename",
				"Surname", roles, true);

		registry.registerUser(origUser);

		GaeUser loadedUser = registry.findUser(userId);

		assertThat(origUser.getUserId()).isEqualTo(loadedUser.getUserId());
		assertThat(loadedUser.isEnabled()).isEqualTo(true);
		assertThat(loadedUser.getAuthorities()).isEqualTo(roles);
		assertThat(loadedUser.getNickname()).isEqualTo("nick");
		assertThat(loadedUser.getEmail()).isEqualTo("nick@blah.com");
		assertThat(loadedUser.getForename()).isEqualTo("Forename");
		assertThat(loadedUser.getSurname()).isEqualTo("Surname");
	}
}
