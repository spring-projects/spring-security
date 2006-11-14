/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package sample.contact;

import java.util.List;


/**
 * Tests {@link
 * com.acegitech.dns.domain.DomainManager#findAllDomainsLike(String)}.
 *
 * @author David Leal
 */
public class GetAllContactsTests extends AbstractContactsSampleTest {
    //~ Methods ================================================================

    public void testFindAllDomainsLikeAsDianne() {
        makeActiveUser("dianne"); // has ROLE_USER
        
        List contacts = contactManager.getAll();
        assertEquals(4, contacts.size());
        
        assertContainsContact(Long.toString(4), contacts);
        assertContainsContact(Long.toString(5), contacts);
        assertContainsContact(Long.toString(6), contacts);
        assertContainsContact(Long.toString(8), contacts);
        
        assertNotContainsContact(Long.toString(1), contacts);
        assertNotContainsContact(Long.toString(2), contacts);
        assertNotContainsContact(Long.toString(3), contacts);
        
    }

    public void testFindAllDomainsLikeAsMarissa() {
        makeActiveUser("marissa"); // has ROLE_SUPERVISOR
        
        List contacts = contactManager.getAll();        
        
        assertEquals(4, contacts.size());
        
        assertContainsContact(Long.toString(1), contacts);
        assertContainsContact(Long.toString(2), contacts);
        assertContainsContact(Long.toString(3), contacts);
        assertContainsContact(Long.toString(4), contacts);
        
        assertNotContainsContact(Long.toString(5), contacts);       
              
    }

    public void testFindAllDomainsLikeAsScott() {
        makeActiveUser("scott"); // has ROLE_USER
        
        List contacts = contactManager.getAll();
        
        assertEquals(5, contacts.size());        
        
        assertContainsContact(Long.toString(4), contacts);
        assertContainsContact(Long.toString(6), contacts);
        assertContainsContact(Long.toString(7), contacts);
        assertContainsContact(Long.toString(8), contacts);
        assertContainsContact(Long.toString(9), contacts);
        
        assertNotContainsContact(Long.toString(1), contacts);        
                       
    }
}
