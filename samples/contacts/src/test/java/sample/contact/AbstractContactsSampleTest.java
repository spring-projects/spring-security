package sample.contact;

import java.util.Iterator;
import java.util.List;

import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.context.SecurityContextImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.test.AbstractTransactionalSpringContextTests;

/**
 * Provides simplified access to the <code>ContactManager</code> bean and
 * convenience test support methods.
 * 
 * @author David Leal
 */
/**
 * @author balex
 *
 */
public abstract class AbstractContactsSampleTest extends AbstractTransactionalSpringContextTests {

    protected ContactManager contactManager;

    protected String[] getConfigLocations() {
    	setAutowireMode(AutowireCapableBeanFactory.AUTOWIRE_BY_NAME);
        return new String[] { "applicationContext-common-authorization.xml",
                "applicationContext-common-business.xml",
                "applicationContext-contacts-test.xml" };
    }

    /**
     * Locates the first <code>Contact</code> of the exact name specified.
     * 
     * <p>
     * Uses the {@link ContactManager#getAll()} method.
     * </p>
     * 
     * @param id
     *            Identify of the contact to locate (must be an exact match)
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

    protected void assertNotContainsContact(String id, List contacts) {
        Iterator iter = contacts.iterator();

        while (iter.hasNext()) {
            Contact domain = (Contact) iter.next();

            if (domain.getId().toString().equals(id)) {
                fail("List of contact should NOT (but did) contain: " + id);
            }
        }
    }

    protected void makeActiveUser(String username) {
        String password = "";

        if ("marissa".equals(username)) {
            password = "koala";
        } else if ("dianne".equals(username)) {
            password = "emu";
        } else if ("scott".equals(username)) {
            password = "wombat";
        } else if ("peter".equals(username)) {
            password = "opal";
        }

        Authentication authRequest = new UsernamePasswordAuthenticationToken(
                username, password);
        SecurityContextImpl secureContext = new SecurityContextImpl();
        secureContext.setAuthentication(authRequest);
        SecurityContextHolder.setContext(secureContext);
    }

    protected void onTearDownInTransaction() {
        destroySecureContext();
    }

    private static void destroySecureContext() {
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }

	public void setContactManager(ContactManager contactManager) {
		this.contactManager = contactManager;
	}
}
