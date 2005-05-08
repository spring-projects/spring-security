/* Copyright 2004, 2005 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.attributes;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.context.SecurityContextHolder;
import net.sf.acegisecurity.context.SecurityContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * DOCUMENT ME!
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class Main {
    //~ Methods ================================================================

    public static void main(String[] args) throws Exception {
        createSecureContext();

        ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext(
                "applicationContext.xml");
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
