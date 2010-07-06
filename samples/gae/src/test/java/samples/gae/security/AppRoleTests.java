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



}
