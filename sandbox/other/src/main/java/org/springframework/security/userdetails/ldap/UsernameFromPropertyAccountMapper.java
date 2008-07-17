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
package org.springframework.security.userdetails.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.AuthenticationException;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Maps user (loaded from the primary user accounts repository, e.g. LDAP) to username in secondary
 * user accounts repository. Maps all users to the same <tt>username</tt>.
 * 
 * 
 * @author Valery Tydykov
 * 
 */
public class UsernameFromPropertyAccountMapper implements AccountMapper, InitializingBean {
    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    // single username to map to
    private String username;

    public String map(UserDetails user) throws AuthenticationException {
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Mapping account=[" + user.getUsername() + "] to account=["
                    + this.getUsername() + "]");
        }

        // map all users to the same userName
        return this.getUsername();
    }

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(username, "userName must be not empty");
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * @param username the username to set
     */
    public void setUsername(String username) {
        Assert.hasLength(username, "userName must be not empty");
        this.username = username;
    }
}
