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

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.AbstractAuthenticationManager;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.concurrent.ConcurrentSessionController;
import net.sf.acegisecurity.concurrent.NullConcurrentSessionController;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.util.Iterator;
import java.util.List;


/**
 * Iterates an {@link Authentication} request through a list of {@link
 * AuthenticationProvider}s. Can optionally be configured with a {@link
 * ConcurrentSessionController} to limit the number of sessions a user can
 * have.
 * 
 * <p>
 * <code>AuthenticationProvider</code>s are tried in order until one provides a
 * non-null response. A non-null response indicates the provider had authority
 * to decide on the authentication request and no further providers are tried.
 * If an <code>AuthenticationException</code> is thrown by a provider, it is
 * retained until subsequent providers are tried. If a subsequent provider
 * successfully authenticates the request, the earlier authentication
 * exception is disregarded and the successful authentication will be used. If
 * no subsequent provider provides a non-null response, or a new
 * <code>AuthenticationException</code>, the last
 * <code>AuthenticationException</code> received will be used. If no provider
 * returns a non-null response, or indicates it can even process an
 * <code>Authentication</code>, the <code>ProviderManager</code> will throw a
 * <code>ProviderNotFoundException</code>.
 * </p>
 *
 * @author Ben Alex
 * @author Wesley Hall
 * @author Ray Krueger
 * @version $Id$
 *
 * @see ConcurrentSessionController
 */
public class ProviderManager extends AbstractAuthenticationManager
    implements InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ProviderManager.class);

    //~ Instance fields ========================================================

    private ConcurrentSessionController sessionController = new NullConcurrentSessionController();
    private List providers;

    //~ Methods ================================================================

    /**
     * Sets the {@link AuthenticationProvider} objects to be used for
     * authentication.
     *
     * @param newList
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public void setProviders(List newList) {
        checkIfValidList(newList);

        Iterator iter = newList.iterator();

        while (iter.hasNext()) {
            Object currentObject = null;

            try {
                currentObject = iter.next();

                AuthenticationProvider attemptToCast = (AuthenticationProvider) currentObject;
            } catch (ClassCastException cce) {
                throw new IllegalArgumentException("AuthenticationProvider "
                    + currentObject.getClass().getName()
                    + " must implement AuthenticationProvider");
            }
        }

        this.providers = newList;
    }

    public List getProviders() {
        return this.providers;
    }

    /**
     * Set the {@link ConcurrentSessionController} to be used for limiting
     * user's sessions.  The {@link NullConcurrentSessionController} is used
     * by default
     *
     * @param sessionController {@link ConcurrentSessionController}
     */
    public void setSessionController(
        ConcurrentSessionController sessionController) {
        this.sessionController = sessionController;
    }

    /**
     * The configured {@link ConcurrentSessionController} is returned or the
     * {@link NullConcurrentSessionController} if a specific one has not been
     * set.
     *
     * @return {@link ConcurrentSessionController} instance
     */
    public ConcurrentSessionController getSessionController() {
        return sessionController;
    }

    public void afterPropertiesSet() throws Exception {
        checkIfValidList(this.providers);
    }

    /**
     * Attempts to authenticate the passed {@link Authentication} object.
     * 
     * <p>
     * The list of {@link AuthenticationProvider}s will be successively tried
     * until an <code>AuthenticationProvider</code> indicates it is  capable
     * of authenticating the type of <code>Authentication</code> object
     * passed. Authentication will then be attempted with that
     * <code>AuthenticationProvider</code>.
     * </p>
     * 
     * <p>
     * If more than one <code>AuthenticationProvider</code> supports the passed
     * <code>Authentication</code> object, only the first
     * <code>AuthenticationProvider</code> tried will determine the result. No
     * subsequent <code>AuthenticationProvider</code>s will be tried.
     * </p>
     *
     * @param authentication the authentication request object.
     *
     * @return a fully authenticated object including credentials.
     *
     * @throws AuthenticationException if authentication fails.
     * @throws ProviderNotFoundException DOCUMENT ME!
     */
    public Authentication doAuthentication(Authentication authentication)
        throws AuthenticationException {
        Iterator iter = providers.iterator();

        Class toTest = authentication.getClass();

        sessionController.checkAuthenticationAllowed(authentication);

        AuthenticationException lastException = null;

        while (iter.hasNext()) {
            AuthenticationProvider provider = (AuthenticationProvider) iter
                .next();

            if (provider.supports(toTest)) {
                logger.debug("Authentication attempt using "
                    + provider.getClass().getName());

                Authentication result = null;

                try {
                    result = provider.authenticate(authentication);
                } catch (AuthenticationException ae) {
                    lastException = ae;
                }

                if (result != null) {
                    sessionController.registerSuccessfulAuthentication(result);

                    return result;
                }
            }
        }

        if (lastException != null) {
            throw lastException;
        }

        throw new ProviderNotFoundException("No authentication provider for "
            + toTest.getName());
    }

    private void checkIfValidList(List listToCheck) {
        if ((listToCheck == null) || (listToCheck.size() == 0)) {
            throw new IllegalArgumentException(
                "A list of AuthenticationManagers is required");
        }
    }
}
