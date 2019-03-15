/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.userdetails.memory;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.util.Properties;


/**
 * Retrieves user details from an in-memory list created by the bean context.
 *
 * @author Ben Alex
 * @deprecated Use InMemoryUserDetailsManager instead (or write your own implementation)
 */
@Deprecated
public class InMemoryDaoImpl implements UserDetailsService, InitializingBean {
    //~ Instance fields ================================================================================================

    private UserMap userMap;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userMap,
            "A list of users, passwords, enabled/disabled status and their granted authorities must be set");
    }

    public UserMap getUserMap() {
        return userMap;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userMap.getUser(username);
    }

    public void setUserMap(UserMap userMap) {
        this.userMap = userMap;
    }

    /**
     * Modifies the internal <code>UserMap</code> to reflect the <code>Properties</code> instance passed. This
     * helps externalise user information to another file etc.
     *
     * @param props the account information in a <code>Properties</code> object format
     */
    public void setUserProperties(Properties props) {
        UserMap userMap = new UserMap();
        this.userMap = UserMapEditor.addUsersFromProperties(userMap, props);
    }
}
