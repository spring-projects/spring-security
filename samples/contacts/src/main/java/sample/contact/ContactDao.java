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

import java.util.List;


/**
 * Provides access to the application's persistence layer.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ContactDao {
    //~ Methods ================================================================

    public Contact getById(Integer id);

    public void create(Contact contact);

    /**
     * Creates an acl_object_identity for the specified Contact.
     *
     * @param contact to create an entry for
     *
     * @return the acl_object_identity identifier
     */
    public Integer createAclObjectIdentity(Contact contact);

    /**
     * Given an acl_object_identitiy identifier, grant the specified recipient
     * read access to the object identified.
     *
     * @param aclObjectIdentity to assign the read permission against
     * @param recipient receiving the permission
     * @param permission to assign
     */
    public void createPermission(Integer aclObjectIdentity, String recipient,
        int permission);

    public void delete(Integer contactId);

    public void deletePermission(Integer aclObjectIdentity, String recipient);

    public List findAll();

    public List findAllPrincipals();

    public List findAllRoles();

    /**
     * Obtains the acl_object_identity for the specified Contact.
     *
     * @param contact to locate an acl_object_identity for
     *
     * @return the acl_object_identity identifier or <code>null</code> if not
     *         found
     */
    public Integer lookupAclObjectIdentity(Contact contact);

    public void update(Contact contact);
}
