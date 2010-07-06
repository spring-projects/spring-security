package samples.gae.users;

import static org.junit.Assert.assertEquals;

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
    private final LocalServiceTestHelper helper =
        new LocalServiceTestHelper(new LocalDatastoreServiceTestConfig());

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
        GaeDataStoreUserRegistry registry = new GaeDataStoreUserRegistry();

        Set<AppRole> roles = EnumSet.of(AppRole.ADMIN, AppRole.USER);
        String userId = "someUserId";

        GaeUser origUser = new GaeUser(userId, "nick", "nick@blah.com", "Forename", "Surname", roles, true);

        registry.registerUser(origUser);

        GaeUser loadedUser = registry.findUser(userId);

        assertEquals(loadedUser.getUserId(), origUser.getUserId());
        assertEquals(true, loadedUser.isEnabled());
        assertEquals(roles, loadedUser.getAuthorities());
        assertEquals("nick", loadedUser.getNickname());
        assertEquals("nick@blah.com", loadedUser.getEmail());
        assertEquals("Forename", loadedUser.getForename());
        assertEquals("Surname", loadedUser.getSurname());
    }
}
