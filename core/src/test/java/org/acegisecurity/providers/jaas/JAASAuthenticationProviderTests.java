package net.sf.acegisecurity.providers.jaas;

import junit.framework.TestCase;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.springframework.context.support.FileSystemXmlApplicationContext;

import java.util.Arrays;
import java.util.List;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 16, 2004<br>
 */
public class JAASAuthenticationProviderTests extends TestCase {

    private JAASAuthenticationProvider jaasProvider;

    protected void setUp() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        FileSystemXmlApplicationContext context = new FileSystemXmlApplicationContext(getClass().getResource(resName).toString());
        jaasProvider = (JAASAuthenticationProvider) context.getBean("jaasAuthenticationProvider");
    }

    public void testFull() throws Exception {

        GrantedAuthorityImpl role1 = new GrantedAuthorityImpl("ROLE_1");
        GrantedAuthorityImpl role2 = new GrantedAuthorityImpl("ROLE_2");

        GrantedAuthority[] defaultAuths = new GrantedAuthority[]{
            role1,
            role2,
        };

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password", defaultAuths);

        Authentication auth = jaasProvider.authenticate(token);

        List list = Arrays.asList(auth.getAuthorities());

        assertTrue("GrantedAuthorities does not contain ROLE_TEST",
                list.contains(new GrantedAuthorityImpl("ROLE_TEST")));

        assertTrue("GrantedAuthorities does not contain ROLE_1", list.contains(role1));

        assertTrue("GrantedAuthorities does not contain ROLE_2", list.contains(role2));
    }

    public void testBadUser() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("asdf", "password"));
            fail("LoginException should have been thrown for the bad user");
        } catch (AuthenticationException e) {
        }
    }

    public void testBadPassword() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("user", "asdf"));
            fail("LoginException should have been thrown for the bad password");
        } catch (AuthenticationException e) {
        }
    }

}
