/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.attributes;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests security objects.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BankTests extends TestCase {
    //~ Instance fields ========================================================

    private BankService service;
    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public BankTests() {
        super();
    }

    public BankTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext("applicationContext.xml");
        service = (BankService) ctx.getBean("bankService");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BankTests.class);
    }

    public void testDeniedAccess() throws Exception {
        createSecureContext();

        try {
            service.balance("1");
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        destroySecureContext();
    }

    public void testListAccounts() throws Exception {
        createSecureContext();
        service.listAccounts();
        destroySecureContext();
    }

    private static void createSecureContext() {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("test",
                                                                         "test",
                                                                         new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_TELLER"), new GrantedAuthorityImpl("ROLE_PERMISSION_LIST")});

        SecureContextImpl secureContext = new SecureContextImpl();
        secureContext.setAuthentication(auth);
        ContextHolder.setContext(secureContext);
    }

    private static void destroySecureContext() {
        ContextHolder.setContext(null);
    }
}
