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

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.providers.dao.User;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;


/**
 * Used by {@link InMemoryDaoImpl} to store a list of users and their
 * corresponding granted authorities.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserMap {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(UserMap.class);

    //~ Instance fields ========================================================

    private Map userMap = new HashMap();

    //~ Methods ================================================================

    public User getUser(String username) {
        return (User) this.userMap.get(username.toLowerCase());
    }

    /**
     * Adds a user to the in-memory map.
     *
     * @param user the user to be stored
     */
    public void addUser(User user) {
        logger.info("Adding user [" + user + "]");
        this.userMap.put(user.getUsername().toLowerCase(), user);
    }
}
