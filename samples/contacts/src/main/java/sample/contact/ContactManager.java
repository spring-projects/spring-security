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
 * Interface for the application's services layer.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ContactManager {
    //~ Methods ================================================================

    public List getAll();

    public List getAllRecipients();

    public Contact getById(Integer id);

    public Contact getRandomContact();

    public void addPermission(Contact contact, String recipient,
        Integer permission);

    public void create(Contact contact);

    public void delete(Contact contact);

    public void deletePermission(Contact contact, String recipient);
}
