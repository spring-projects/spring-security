package net.sf.acegisecurity.providers.jaas;

import junit.framework.TestCase;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.Arrays;
import java.util.List;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JaasAuthenticationProviderTests extends TestCase {

    private JaasAuthenticationProvider jaasProvider;
    private ApplicationContext context;
    private JaasEventCheck eventCheck;

    protected void setUp() throws Exception {
        String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
        context = new ClassPathXmlApplicationContext(resName);
        eventCheck = (JaasEventCheck) context.getBean("eventCheck");
        jaasProvider = (JaasAuthenticationProvider) context.getBean("jaasAuthenticationProvider");
    }

    public void testFull() throws Exception {

        GrantedAuthorityImpl role1 = new GrantedAuthorityImpl("ROLE_1");
        GrantedAuthorityImpl role2 = new GrantedAuthorityImpl("ROLE_2");

        GrantedAuthority[] defaultAuths = new GrantedAuthority[]{
            role1,
            role2,
        };

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password", defaultAuths);

        assertTrue(jaasProvider.supports(UsernamePasswordAuthenticationToken.class));

        Authentication auth = jaasProvider.authenticate(token);

        assertNotNull(jaasProvider.getAuthorityGranters());
        assertNotNull(jaasProvider.getCallbackHandlers());
        assertNotNull(jaasProvider.getLoginConfig());
        assertNotNull(jaasProvider.getLoginContextName());

        List list = Arrays.asList(auth.getAuthorities());

        assertTrue("GrantedAuthorities does not contain ROLE_TEST",
                list.contains(new GrantedAuthorityImpl("ROLE_TEST")));

        assertTrue("GrantedAuthorities does not contain ROLE_1", list.contains(role1));

        assertTrue("GrantedAuthorities does not contain ROLE_2", list.contains(role2));

        boolean foundit = false;
        for (int i = 0; i < list.size(); i++) {
            Object obj = list.get(i);
            if (obj instanceof JaasGrantedAuthority) {
                JaasGrantedAuthority grant = (JaasGrantedAuthority) obj;
                assertNotNull("Principal was null on JaasGrantedAuthority", grant.getPrincipal());
                foundit = true;
            }
        }
        assertTrue("Could not find a JaasGrantedAuthority", foundit);

        assertNotNull("Success event not fired", eventCheck.successEvent);
        assertEquals("Auth objects are not equal", auth, eventCheck.successEvent.getAuthentication());

        assertNull("Failure event was fired", eventCheck.failedEvent);
    }

    public void testBadUser() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("asdf", "password"));
            fail("LoginException should have been thrown for the bad user");
        } catch (AuthenticationException e) {
        }

        assertNotNull("Failure event not fired", eventCheck.failedEvent);
        assertNotNull("Failure event exception was null", eventCheck.failedEvent.getException());
        assertNull("Success event was fired", eventCheck.successEvent);
    }

    public void testBadPassword() {
        try {
            jaasProvider.authenticate(new UsernamePasswordAuthenticationToken("user", "asdf"));
            fail("LoginException should have been thrown for the bad password");
        } catch (AuthenticationException e) {
        }

        assertNotNull("Failure event not fired", eventCheck.failedEvent);
        assertNotNull("Failure event exception was null", eventCheck.failedEvent.getException());
        assertNull("Success event was fired", eventCheck.successEvent);
    }

}
