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

package sample.contact.annotation;

import java.util.List;
import java.util.Random;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.acl.basic.AclObjectIdentity;
import net.sf.acegisecurity.acl.basic.BasicAclExtendedDao;
import net.sf.acegisecurity.acl.basic.NamedEntityObjectIdentity;
import net.sf.acegisecurity.acl.basic.SimpleAclEntry;
import net.sf.acegisecurity.annotation.Secured;
import net.sf.acegisecurity.context.SecurityContextHolder;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.ApplicationObjectSupport;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import sample.contact.Contact;
import sample.contact.ContactDao;
import sample.contact.ContactManager;


/**
 * Concrete implementation of Java 5 Annotated {@link ContactManager}.
 *
 * @author Mark St.Godard
 * @version $Id$
 */
@Transactional
public class ContactManagerBackend extends ApplicationObjectSupport
    implements ContactManager, InitializingBean {
    //~ Instance fields ========================================================

    private BasicAclExtendedDao basicAclExtendedDao;
    private ContactDao contactDao;
    private int counter = 100;

    //~ Methods ================================================================

    @Secured ({"ROLE_USER","AFTER_ACL_COLLECTION_READ"})
    @Transactional(readOnly=true)
    public List getAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning all contacts");
        }

        return contactDao.findAll();
    }

    @Secured ({"ROLE_USER"})
    @Transactional(readOnly=true)
    public List getAllRecipients() {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning all recipients");
        }

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

    @Secured ({"ROLE_USER","AFTER_ACL_READ"})
    @Transactional(readOnly=true)
    public Contact getById(Long id) {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning contact with id: " + id);
        }

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
        if (logger.isDebugEnabled()) {
            logger.debug("Returning random contact");
        }

        Random rnd = new Random();
        List contacts = contactDao.findAll();
        int getNumber = rnd.nextInt(contacts.size());

        return (Contact) contacts.get(getNumber);
    }

    @Secured ({"ACL_CONTACT_ADMIN"})
    public void addPermission(Contact contact, String recipient,
        Integer permission) {
        SimpleAclEntry simpleAclEntry = new SimpleAclEntry();
        simpleAclEntry.setAclObjectIdentity(makeObjectIdentity(contact));
        simpleAclEntry.setMask(permission.intValue());
        simpleAclEntry.setRecipient(recipient);
        basicAclExtendedDao.create(simpleAclEntry);

        if (logger.isDebugEnabled()) {
            logger.debug("Added permission " + permission + " for recipient "
                + recipient + " contact " + contact);
        }
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(contactDao, "contactDao required");
        Assert.notNull(basicAclExtendedDao, "basicAclExtendedDao required");
    }

    @Secured ({"ROLE_USER"})
    public void create(Contact contact) {
        // Create the Contact itself
        contact.setId(new Long(counter++));
        contactDao.create(contact);

        // Grant the current principal access to the contact 
        addPermission(contact, getUsername(),
            new Integer(SimpleAclEntry.ADMINISTRATION));

        if (logger.isDebugEnabled()) {
            logger.debug("Created contact " + contact
                + " and granted admin permission to recipient " + getUsername());
        }
    }

    @Secured ({"ACL_CONTACT_DELETE"})
    public void delete(Contact contact) {
        contactDao.delete(contact.getId());

        // Delete the ACL information as well
        basicAclExtendedDao.delete(makeObjectIdentity(contact));

        if (logger.isDebugEnabled()) {
            logger.debug("Deleted contact " + contact
                + " including ACL permissions");
        }
    }

    @Secured ({"ACL_CONTACT_ADMIN"})
    public void deletePermission(Contact contact, String recipient) {
        basicAclExtendedDao.delete(makeObjectIdentity(contact), recipient);

        if (logger.isDebugEnabled()) {
            logger.debug("Deleted contact " + contact
                + " ACL permissions for recipient " + recipient);
        }
    }

    public void update(Contact contact) {
        contactDao.update(contact);

        if (logger.isDebugEnabled()) {
            logger.debug("Updated contact " + contact);
        }
    }

    protected String getUsername() {
        Authentication auth = SecurityContextHolder.getContext()
                                                   .getAuthentication();

        if (auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            return auth.getPrincipal().toString();
        }
    }

    private AclObjectIdentity makeObjectIdentity(Contact contact) {
        return new NamedEntityObjectIdentity(contact.getClass().getName(),
            contact.getId().toString());
    }
}
