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
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataAccessException;


/**
 * Retrieves user details from an in-memory list created by the bean context.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InMemoryDaoImpl implements AuthenticationDao, InitializingBean {
    //~ Instance fields ========================================================

    private UserMap userMap;

    //~ Methods ================================================================

    public void setUserMap(UserMap userMap) {
        this.userMap = userMap;
    }

    public UserMap getUserMap() {
        return userMap;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.userMap == null) {
            throw new IllegalArgumentException(
                "A list of users, passwords, enabled/disabled status and their granted authorities must be set");
        }
    }

    public UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException, DataAccessException {
        return userMap.getUser(username);
    }
}
