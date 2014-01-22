package samples.gae.security;

import static org.junit.Assert.*;
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

        assertEquals("ADMIN", admin.getAuthority());
    }

    @Test
    public void bitsAreCorrect() throws Exception {
        // If this fails, someone has modified the Enum and the Datastore is probably corrupt!
        assertEquals(0, ADMIN.getBit());
        assertEquals(1, NEW_USER.getBit());
        assertEquals(2, USER.getBit());
    }
}
