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

package net.sf.acegisecurity.acl;

import net.sf.acegisecurity.Authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.util.Iterator;
import java.util.List;


/**
 * Iterates through a list of {@link AclProvider}s to locate the ACLs that
 * apply to a given domain object instance.
 * 
 * <P>
 * If no compatible provider is found, it is assumed that no ACLs apply for the
 * specified domain object instance and <code>null</code> is returned.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclProviderManager implements AclManager, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(AclProviderManager.class);

    //~ Instance fields ========================================================

    private List providers;

    //~ Methods ================================================================

    public AclEntry[] getAcls(Object domainInstance) {
        if (domainInstance == null) {
            throw new IllegalArgumentException(
                "domainInstance is null - violating interface contract");
        }

        Iterator iter = providers.iterator();

        while (iter.hasNext()) {
            AclProvider provider = (AclProvider) iter.next();

            if (provider.supports(domainInstance)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("ACL lookup using "
                        + provider.getClass().getName());
                }

                return provider.getAcls(domainInstance);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No AclProvider found for "
                + domainInstance.toString());
        }

        return null;
    }

	public AclEntry[] getAcls(Object domainInstance,
			Authentication authentication) {
        if (domainInstance == null) {
            throw new IllegalArgumentException(
                "domainInstance is null - violating interface contract");
        }
        if (authentication == null) {
            throw new IllegalArgumentException(
                "authentication is null - violating interface contract");
        }

        Iterator iter = providers.iterator();

        while (iter.hasNext()) {
            AclProvider provider = (AclProvider) iter.next();

            if (provider.supports(domainInstance)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("ACL lookup using "
                        + provider.getClass().getName());
                }

                return provider.getAcls(domainInstance, authentication);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No AclProvider found for "
                + domainInstance.toString());
        }

        return null;
	}
	
    /**
     * Sets the {@link AclProvider} objects to be used for ACL determinations.
     *
     * @param newList that should be used for ACL determinations
     *
     * @throws IllegalArgumentException if an invalid provider was included in
     *         the list
     */
    public void setProviders(List newList) {
        checkIfValidList(newList);

        Iterator iter = newList.iterator();

        while (iter.hasNext()) {
            Object currentObject = null;

            try {
                currentObject = iter.next();

                AclProvider attemptToCast = (AclProvider) currentObject;
            } catch (ClassCastException cce) {
                throw new IllegalArgumentException("AclProvider "
                    + currentObject.getClass().getName()
                    + " must implement AclProvider");
            }
        }

        this.providers = newList;
    }

    public List getProviders() {
        return this.providers;
    }

    public void afterPropertiesSet() throws Exception {
        checkIfValidList(this.providers);
    }

    private void checkIfValidList(List listToCheck) {
        if ((listToCheck == null) || (listToCheck.size() == 0)) {
            throw new IllegalArgumentException(
                "A list of AclManagers is required");
        }
    }
}
