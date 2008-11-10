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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Iterator;
import java.util.List;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.Authentication;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


/**
 * Tests {@link ContactManager}.
 *
 * @author David Leal
 * @author Ben Alex
 */
@ContextConfiguration(locations={
                "/applicationContext-common-authorization.xml",
                "/applicationContext-common-business.xml",
                "/applicationContext-contacts-test.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class GetAllContactsTests {
    //~ Instance fields ================================================================================================

    @Autowired
    protected ContactManager contactManager;

    //~ Methods ========================================================================================================

    protected void assertContainsContact(String id, List contacts) {
        Iterator iter = contacts.iterator();
        System.out.println(contacts);

        while (iter.hasNext()) {
            Contact contact = (Contact) iter.next();

            if (contact.getId().toString().equals(id)) {
                return;
            }
        }

        fail("List of contacts should have contained: " + id);
    }

    void assertDoestNotContainContact(String id, List contacts) {
        Iterator iter = contacts.iterator();

        while (iter.hasNext()) {
            Contact domain = (Contact) iter.next();

            if (domain.getId().toString().equals(id)) {
                fail("List of contact should NOT (but did) contain: " + id);
            }
        }
    }

    /**
     * Locates the first <code>Contact</code> of the exact name specified.<p>Uses the {@link
     * ContactManager#getAll()} method.</p>
     *
     * @param id Identify of the contact to locate (must be an exact match)
     *
     * @return the domain or <code>null</code> if not found
     */
    protected Contact getContact(String id) {
        List contacts = contactManager.getAll();
        Iterator iter = contacts.iterator();

        while (iter.hasNext()) {
            Contact contact = (Contact) iter.next();

            if (contact.getId().equals(id)) {
                return contact;
            }
        }

        return null;
    }

    protected void makeActiveUser(String username) {
        String password = "";

        if ("rod".equals(username)) {
            password = "koala";
        } else if ("dianne".equals(username)) {
            password = "emu";
        } else if ("scott".equals(username)) {
            password = "wombat";
        } else if ("peter".equals(username)) {
            password = "opal";
        }

        Authentication authRequest = new UsernamePasswordAuthenticationToken(username, password);
        SecurityContextHolder.getContext().setAuthentication(authRequest);
    }

    @After
    public void onTearDownInTransaction() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testDianne() {
        makeActiveUser("dianne"); // has ROLE_USER

        List contacts = contactManager.getAll();
        assertEquals(4, contacts.size());

        assertContainsContact(Long.toString(4), contacts);
        assertContainsContact(Long.toString(5), contacts);
        assertContainsContact(Long.toString(6), contacts);
        assertContainsContact(Long.toString(8), contacts);

        assertDoestNotContainContact(Long.toString(1), contacts);
        assertDoestNotContainContact(Long.toString(2), contacts);
        assertDoestNotContainContact(Long.toString(3), contacts);
    }

    @Test
    public void testrod() {
        makeActiveUser("rod"); // has ROLE_SUPERVISOR

        List contacts = contactManager.getAll();

        assertEquals(4, contacts.size());

        assertContainsContact(Long.toString(1), contacts);
        assertContainsContact(Long.toString(2), contacts);
        assertContainsContact(Long.toString(3), contacts);
        assertContainsContact(Long.toString(4), contacts);

        assertDoestNotContainContact(Long.toString(5), contacts);

        Contact c1 = contactManager.getById(new Long(4));

        contactManager.deletePermission(c1, new PrincipalSid("bob"), BasePermission.ADMINISTRATION);
    }

    @Test
    public void testScott() {
        makeActiveUser("scott"); // has ROLE_USER

        List contacts = contactManager.getAll();

        assertEquals(5, contacts.size());

        assertContainsContact(Long.toString(4), contacts);
        assertContainsContact(Long.toString(6), contacts);
        assertContainsContact(Long.toString(7), contacts);
        assertContainsContact(Long.toString(8), contacts);
        assertContainsContact(Long.toString(9), contacts);

        assertDoestNotContainContact(Long.toString(1), contacts);
    }
}
