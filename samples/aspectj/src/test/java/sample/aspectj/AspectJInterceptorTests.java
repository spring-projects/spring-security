package sample.aspectj;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:aspectj-context.xml")
public class AspectJInterceptorTests {

    @Autowired
    private Service service;

    @Autowired
    private SecuredService securedService;

    @Test
    public void testPublicMethod() throws Exception {
        service.publicMethod();
    }

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void testSecuredMethodNotAuthenticated() throws Exception {
        service.secureMethod();
    }

    @Test(expected = AccessDeniedException.class)
    public void testSecuredMethodWrongRole() throws Exception {
        Authentication token = new UsernamePasswordAuthenticationToken("test", "xxx", AuthorityUtils
                .createAuthorityList("ROLE_ADMIN"));
        SecurityContextHolder.getContext().setAuthentication(token);
        service.secureMethod();
    }

    @Test
    public void testSecuredMethodEverythingOk() throws Exception {
        Authentication token = new UsernamePasswordAuthenticationToken("test", "xxx", AuthorityUtils
                .createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(token);
        service.secureMethod();
    }

    @Test(expected = AuthenticationCredentialsNotFoundException.class)
    public void testSecuredClassNotAuthenticated() throws Exception {
        securedService.secureMethod();
    }

    @Test(expected = AccessDeniedException.class)
    public void testSecuredClassWrongRole() throws Exception {
        Authentication token = new UsernamePasswordAuthenticationToken("test", "xxx", AuthorityUtils
                .createAuthorityList("ROLE_ADMIN"));
        SecurityContextHolder.getContext().setAuthentication(token);
        securedService.secureMethod();
    }

    @Test
    public void testSecuredClassEverythingOk() throws Exception {
        Authentication token = new UsernamePasswordAuthenticationToken("test", "xxx", AuthorityUtils
                .createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(token);
        securedService.secureMethod();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

}
