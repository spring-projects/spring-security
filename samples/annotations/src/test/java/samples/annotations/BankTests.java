package samples.annotations;

import junit.framework.TestCase;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.SecurityContextImpl;
import org.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import sample.annotations.BankService;


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
       ctx = new ClassPathXmlApplicationContext("applicationContext-annotations.xml");
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
               new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_TELLER"), new GrantedAuthorityImpl(
                       "ROLE_PERMISSION_LIST")});

       SecurityContextHolder.getContext().setAuthentication(auth);
   }

   private static void destroySecureContext() {
       SecurityContextHolder.setContext(new SecurityContextImpl());
   }
}

