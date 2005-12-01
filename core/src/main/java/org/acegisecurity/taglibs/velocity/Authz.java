/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.taglibs.velocity;

import org.acegisecurity.Authentication;

import org.acegisecurity.acl.AclManager;

import org.acegisecurity.taglibs.authz.AclTag;
import org.acegisecurity.taglibs.authz.AuthenticationTag;
import org.acegisecurity.taglibs.authz.AuthorizeTag;

import org.acegisecurity.userdetails.UserDetails;

import org.springframework.context.ApplicationContext;


/**
 * Wrapper the implementation of Acegi Security for Spring JSP tag includes:
 * {@link AuthenticationTag}, {@link AclTag}, {@link AuthorizeTag}
 *
 * @author Wang Qi
 * @version $Id$
 */
public interface Authz {
    //~ Methods ================================================================

    /**
     * all the listed roles must be granted to return true, otherwise fasle;
     *
     * @param roles - comma separate GrantedAuthoritys
     *
     * @return granted (true|false)
     */
    public boolean allGranted(String roles);

    /**
     * any the listed roles must be granted to return true, otherwise fasle;
     *
     * @param roles - comma separate GrantedAuthoritys
     *
     * @return granted (true|false)
     */
    public boolean anyGranted(String roles);

    /**
     * set Spring application context which contains acegi related bean
     *
     * @return DOCUMENT ME!
     */
    public ApplicationContext getAppCtx();

    /**
     * return the principal's name, supports the various type of principals
     * that can exist in the {@link Authentication} object, such as a String
     * or {@link UserDetails} instance
     *
     * @return string representation of principal's name
     */
    public String getPrincipal();

    /**
     * return true if the principal holds either permission specified for the
     * provided domain object
     * 
     * <P>
     * Only works with permissions that are subclasses of {@link
     * net.sf.acegisecurity.acl.basic.AbstractBasicAclEntry}.
     * </p>
     * 
     * <p>
     * For this class to operate it must be able to access the application
     * context via the <code>WebApplicationContextUtils</code> and locate an
     * {@link AclManager}.
     * </p>
     *
     * @param domainObject - domain object need acl control
     * @param permissions - comma separate integer permissions
     *
     * @return got acl permission (true|false)
     */
    public boolean hasPermission(Object domainObject, String permissions);

    /**
     * none the listed roles must be granted to return true, otherwise fasle;
     *
     * @param roles - comma separate GrantedAuthoritys
     *
     * @return granted (true|false)
     */
    public boolean noneGranted(String roles);

    /**
     * get Spring application context which contains acegi related bean
     *
     * @param appCtx DOCUMENT ME!
     */
    public void setAppCtx(ApplicationContext appCtx);
}
