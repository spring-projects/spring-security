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

import org.springframework.security.acls.Permission;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.expression.annotation.PostFilter;
import org.springframework.security.expression.annotation.PreAuthorize;

import java.util.List;


/**
 * Interface for the application's services layer.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ContactManager {
    //~ Methods ========================================================================================================
    @PreAuthorize("hasPermission(#contact, admin)")
    public void addPermission(Contact contact, Sid recipient, Permission permission);

    @PreAuthorize("hasPermission(#contact, admin)")
    public void deletePermission(Contact contact, Sid recipient, Permission permission);

    @PreAuthorize("hasRole('ROLE_USER')")
    public void create(Contact contact);

    @PreAuthorize("hasPermission(#contact, 'delete') or hasPermission(#contact, admin)")
    public void delete(Contact contact);

    @PreAuthorize("hasRole('ROLE_USER')")
    @PostFilter("hasPermission(filterObject, 'read') or hasPermission(filterObject, admin)")
    public List getAll();

    @PreAuthorize("hasRole('ROLE_USER')")
    public List getAllRecipients();

    @PreAuthorize(
            "hasPermission(#id, 'sample.contact.Contact', read) or " +
            "hasPermission(#id, 'sample.contact.Contact', admin)")
    public Contact getById(Long id);

    public Contact getRandomContact();
}
