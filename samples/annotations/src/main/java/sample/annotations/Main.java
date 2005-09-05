package sample.annotations;


import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.context.SecurityContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * 
 * @author Mark St.Godard
 * @version $Id$
 */
public class Main {
    //~ Methods ================================================================

    public static void main(String[] args) throws Exception {
        createSecureContext();

        ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext(
                "applicationContext-annotations.xml");
        BankService service = (BankService) context.getBean("bankService");

        // will succeed
        service.listAccounts();

        // will fail
        try {
            System.out.println(
                "We expect an AccessDeniedException now, as we do not hold the ROLE_PERMISSION_BALANCE granted authority, and we're using a unanimous access decision manager... ");
            service.balance("1");
        } catch (AccessDeniedException e) {
            e.printStackTrace();
        }

        destroySecureContext();
    }

    /**
     * This can be done in a web app by using a filter or
     * <code>SpringMvcIntegrationInterceptor</code>.
     */
    private static void createSecureContext() {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("test",
                "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_TELLER"), new GrantedAuthorityImpl(
                        "ROLE_PERMISSION_LIST")});

        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private static void destroySecureContext() {
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }
}
