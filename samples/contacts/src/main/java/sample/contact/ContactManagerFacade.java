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

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.providers.dao.User;

import org.springframework.beans.factory.InitializingBean;


/**
 * This is the public facade to the application's main business object.
 * 
 * <p>
 * Used to demonstrate security configuration in a multi-tier application. Most
 * methods of this class are secured via standard security definitions in the
 * bean context. There is one method that supplements these security checks.
 * All methods delegate to a "backend" object. The "backend" object relies on
 * the facade's <code>RunAsManager</code> assigning an additional
 * <code>GrantedAuthority</code> that is required to call its methods.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContactManagerFacade implements ContactManager, InitializingBean {
    //~ Instance fields ========================================================

    private ContactManager backend;

    //~ Methods ================================================================

    /**
     * Security system will ensure the owner parameter equals the currently
     * logged in user.
     *
     * @param owner DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Contact[] getAllByOwner(String owner) {
        return backend.getAllByOwner(owner);
    }

    public void setBackend(ContactManager backend) {
        this.backend = backend;
    }

    public ContactManager getBackend() {
        return backend;
    }

    /**
     * Security system will ensure logged in user has ROLE_TELLER.
     * 
     * <p>
     * Security system cannot ensure that only the owner can get the contact,
     * as doing so would require it to specifically open the contact. Whilst
     * possible, this would be expensive as the operation would be performed
     * both by the security system as well as the implementation. Instead the
     * facade will confirm the contact.getOwner() matches what is on the
     * ContextHolder.
     * </p>
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws AccessDeniedException DOCUMENT ME!
     */
    public Contact getById(Integer id) {
        Contact result = backend.getById(id);
        Authentication auth = ((SecureContext) ContextHolder.getContext())
            .getAuthentication();

        String username = auth.getPrincipal().toString();

        if (auth.getPrincipal() instanceof User) {
            username = ((User) auth.getPrincipal()).getUsername();
        }

        if (username.equals(result.getOwner())) {
            return result;
        } else {
            throw new AccessDeniedException(
                "The requested id is not owned by the currently logged in user");
        }
    }

    /**
     * Public method.
     *
     * @return DOCUMENT ME!
     */
    public Integer getNextId() {
        return backend.getNextId();
    }

    /**
     * Public method.
     *
     * @return DOCUMENT ME!
     */
    public Contact getRandomContact() {
        return backend.getRandomContact();
    }

    public void afterPropertiesSet() throws Exception {
        if (backend == null) {
            throw new IllegalArgumentException(
                "A backend ContactManager implementation is required");
        }
    }

    /**
     * Security system will ensure logged in user has ROLE_SUPERVISOR.
     *
     * @param contact DOCUMENT ME!
     */
    public void delete(Contact contact) {
        backend.delete(contact);
    }

    /**
     * Security system will ensure the owner specified via contact.getOwner()
     * equals the currently logged in user.
     *
     * @param contact DOCUMENT ME!
     */
    public void save(Contact contact) {
        backend.save(contact);
    }
}
