/* Copyright 2004 Acegi Technology Pty Limited
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

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Vector;


/**
 * Backend business object that manages the contacts.
 * 
 * <P>
 * As a backend, it never faces the public callers. It is always accessed via
 * the {@link ContactManagerFacade}.
 * </p>
 * 
 * <P>
 * This facade approach is not really necessary in this application, and is
 * done simply to demonstrate granting additional authorities via the
 * <code>RunAsManager</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContactManagerBackend implements ContactManager {
    //~ Instance fields ========================================================

    private Map contacts;

    //~ Constructors ===========================================================

    public ContactManagerBackend() {
        this.contacts = new HashMap();
        save(new Contact(this.getNextId(), "John Smith", "john@somewhere.com",
                "marissa"));
        save(new Contact(this.getNextId(), "Michael Citizen",
                "michael@xyz.com", "marissa"));
        save(new Contact(this.getNextId(), "Joe Bloggs", "joe@demo.com",
                "marissa"));
        save(new Contact(this.getNextId(), "Karen Sutherland",
                "karen@sutherland.com", "dianne"));
        save(new Contact(this.getNextId(), "Mitchell Howard",
                "mitchell@abcdef.com", "dianne"));
        save(new Contact(this.getNextId(), "Rose Costas", "rose@xyz.com",
                "scott"));
        save(new Contact(this.getNextId(), "Amanda Smith", "amanda@abcdef.com",
                "scott"));
    }

    //~ Methods ================================================================

    /**
     * Security system expects ROLE_RUN_AS_SERVER
     *
     * @param owner DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Contact[] getAllByOwner(String owner) {
        List list = new Vector();
        Iterator iter = this.contacts.keySet().iterator();

        while (iter.hasNext()) {
            Integer contactId = (Integer) iter.next();
            Contact contact = (Contact) this.contacts.get(contactId);

            if (contact.getOwner().equals(owner)) {
                list.add(contact);
            }
        }

        Contact[] resultType = {new Contact(new Integer(1), "holder", "holder",
                "holder")};

        if (list.size() == 0) {
            return null;
        } else {
            return (Contact[]) list.toArray(resultType);
        }
    }

    /**
     * Security system expects ROLE_RUN_AS_SERVER
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Contact getById(Integer id) {
        return (Contact) this.contacts.get(id);
    }

    /**
     * Public method
     *
     * @return DOCUMENT ME!
     */
    public Integer getNextId() {
        int max = 0;
        Iterator iter = this.contacts.keySet().iterator();

        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();

            if (id.intValue() > max) {
                max = id.intValue();
            }
        }

        return new Integer(max + 1);
    }

    /**
     * This is a public method, meaning a client could call this method
     * directly (ie not via a facade). If this was an issue, the public method
     * on the facade should not be public but secure. Quite possibly an
     * AnonymousAuthenticationToken and associated provider could be used on a
     * secure method, thus allowing a RunAsManager to protect the backend.
     *
     * @return DOCUMENT ME!
     */
    public Contact getRandomContact() {
        Random rnd = new Random();
        int getNumber = rnd.nextInt(this.contacts.size()) + 1;
        Iterator iter = this.contacts.keySet().iterator();
        int i = 0;

        while (iter.hasNext()) {
            i++;

            Integer id = (Integer) iter.next();

            if (i == getNumber) {
                return (Contact) this.contacts.get(id);
            }
        }

        return null;
    }

    /**
     * Security system expects ROLE_RUN_AS_SERVER
     *
     * @param contact DOCUMENT ME!
     */
    public void delete(Contact contact) {
        this.contacts.remove(contact.getId());
    }

    /**
     * Security system expects ROLE_RUN_AS_SERVER
     *
     * @param contact DOCUMENT ME!
     */
    public void save(Contact contact) {
        this.contacts.put(contact.getId(), contact);
    }
}
