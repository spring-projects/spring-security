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
import org.springframework.security.AuthenticationException;
import org.springframework.security.userdetails.UserDetails;

/**
 * Maps user (loaded from the primary user accounts repository, e.g. LDAP) to username in secondary
 * user accounts repository. One-to-one mapping, e.g. maps user with <tt>username</tt> to user
 * with the same <tt>username</tt>.
 * 
 * @author Joel Emery
 * 
 */
public class UsernameFromUserdetailsAccountMapper implements AccountMapper {
    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    public String map(UserDetails user) throws AuthenticationException {
        // get username from UserDetails
        String username = user.getUsername();

        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Mapping account=[" + username + "] to account=[" + username + "]");
        }

        // map cn to userName
        return username;
    }
}
