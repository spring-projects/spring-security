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

import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;

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

    /**
     * Locates the specified user by performing a case insensitive search by
     * username.
     *
     * @param username to find
     *
     * @return the located user
     *
     * @throws UsernameNotFoundException if the user could not be found
     */
    public User getUser(String username) throws UsernameNotFoundException {
        User result = (User) this.userMap.get(username.toLowerCase());

        if (result == null) {
            throw new UsernameNotFoundException("Could not find user: "
                + username);
        }

        return result;
    }

    /**
     * Indicates the size of the user map.
     *
     * @return the number of users in the map
     */
    public int getUserCount() {
        return this.userMap.size();
    }

    /**
     * Adds a user to the in-memory map.
     *
     * @param user the user to be stored
     *
     * @throws IllegalArgumentException if a null User was passed
     */
    public void addUser(UserDetails user) throws IllegalArgumentException {
        if (user == null) {
            throw new IllegalArgumentException("Must be a valid User");
        }

        logger.info("Adding user [" + user + "]");
        this.userMap.put(user.getUsername().toLowerCase(), user);
    }
}
