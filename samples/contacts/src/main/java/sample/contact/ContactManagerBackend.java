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

import net.sf.acegisecurity.acl.basic.AclObjectIdentity;
import net.sf.acegisecurity.acl.basic.BasicAclExtendedDao;
import net.sf.acegisecurity.acl.basic.NamedEntityObjectIdentity;
import net.sf.acegisecurity.acl.basic.SimpleAclEntry;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import org.springframework.beans.factory.InitializingBean;

import java.util.List;
import java.util.Random;


/**
 * Concrete implementation of {@link ContactManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContactManagerBackend implements ContactManager, InitializingBean {
    //~ Instance fields ========================================================

    private BasicAclExtendedDao basicAclExtendedDao;
    private ContactDao contactDao;
    private int counter = 100;

    //~ Methods ================================================================

    public List getAll() {
        return contactDao.findAll();
    }

    public List getAllRecipients() {
        List list = contactDao.findAllPrincipals();
        list.addAll(contactDao.findAllRoles());

        return list;
    }

    public void setBasicAclExtendedDao(BasicAclExtendedDao basicAclExtendedDao) {
        this.basicAclExtendedDao = basicAclExtendedDao;
    }

    public BasicAclExtendedDao getBasicAclExtendedDao() {
        return basicAclExtendedDao;
    }

    public Contact getById(Integer id) {
        return contactDao.getById(id);
    }

    public void setContactDao(ContactDao contactDao) {
        this.contactDao = contactDao;
    }

    public ContactDao getContactDao() {
        return contactDao;
    }

    /**
     * This is a public method.
     *
     * @return DOCUMENT ME!
     */
    public Contact getRandomContact() {
        Random rnd = new Random();
        List contacts = contactDao.findAll();
        int getNumber = rnd.nextInt(contacts.size());

        return (Contact) contacts.get(getNumber);
    }

    public void addPermission(Contact contact, String recipient,
        Integer permission) {
        SimpleAclEntry simpleAclEntry = new SimpleAclEntry();
        simpleAclEntry.setAclObjectIdentity(makeObjectIdentity(contact));
        simpleAclEntry.setMask(permission.intValue());
        simpleAclEntry.setRecipient(recipient);
        basicAclExtendedDao.create(simpleAclEntry);
    }

    public void afterPropertiesSet() throws Exception {
        if (contactDao == null) {
            throw new IllegalArgumentException("contactDao required");
        }

        if (basicAclExtendedDao == null) {
            throw new IllegalArgumentException("basicAclExtendedDao required");
        }
    }

    public void create(Contact contact) {
        // Create the Contact itself
        contact.setId(new Integer(counter++));
        contactDao.create(contact);

        // Grant the current principal access to the contact 
        addPermission(contact, getUsername(),
            new Integer(SimpleAclEntry.ADMINISTRATION));
    }

    public void delete(Contact contact) {
        contactDao.delete(contact.getId());

        // Delete the ACL information as well
        basicAclExtendedDao.delete(makeObjectIdentity(contact));
    }

    public void deletePermission(Contact contact, String recipient) {
        basicAclExtendedDao.delete(makeObjectIdentity(contact), recipient);
    }

    public void update(Contact contact) {
        contactDao.update(contact);
    }

    protected String getUsername() {
        return ((SecureContext) ContextHolder.getContext()).getAuthentication()
                .getPrincipal().toString();
    }

    private AclObjectIdentity makeObjectIdentity(Contact contact) {
        return new NamedEntityObjectIdentity(contact.getClass().getName(),
            contact.getId().toString());
    }
}
