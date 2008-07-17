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

import org.springframework.security.AuthenticationException;
import org.springframework.security.userdetails.UserDetails;

/**
 * Maps user (loaded from the primary user accounts repository, e.g. LDAP) to username in secondary
 * user accounts repository.
 * 
 * 
 * @author Valery Tydykov
 * 
 */
public interface AccountMapper {

    /**
     * Map user to username in secondary user accounts repository.
     * 
     * @param user, loaded from the primary user accounts repository.
     * @return username for secondary user accounts repository.
     * @throws AuthenticationException if can not map given user.
     */
    String map(UserDetails user) throws AuthenticationException;
}
