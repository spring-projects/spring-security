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

package org.springframework.security.taglibs.velocity;


import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;


/**
 * @author Wang Qi
 */
public interface Authz {
    //~ Methods ========================================================================================================

    /**
     * all the listed roles must be granted to return true, otherwise false;
     *
     * @param roles - comma separate GrantedAuthoritys
     *
     * @return granted (true|false)
     */
    boolean allGranted(String roles);

    /**
     * any the listed roles must be granted to return true, otherwise false;
     *
     * @param roles - comma separate GrantedAuthoritys
     *
     * @return granted (true|false)
     */
    boolean anyGranted(String roles);

    /**
     * get Spring application context which contains
     *
     */
    ApplicationContext getAppCtx();

    /**
     * return the principal's name, supports the various type of principals that can exist in the {@link
     * Authentication} object, such as a String or {@link UserDetails} instance
     *
     * @return string representation of principal's name
     */
    String getPrincipal();

    /**
     * none the listed roles must be granted to return true, otherwise false;
     *
     * @param roles - comma separate GrantedAuthoritys
     *
     * @return granted (true|false)
     */
    boolean noneGranted(String roles);

    /**
     * set Spring application context which contains Acegi related bean
     *
     */
    void setAppCtx(ApplicationContext appCtx);
}
