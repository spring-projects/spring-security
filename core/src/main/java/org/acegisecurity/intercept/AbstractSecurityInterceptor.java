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

package net.sf.acegisecurity.intercept;

import net.sf.acegisecurity.AccessDecisionManager;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationCredentialsNotFoundException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.RunAsManager;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * Abstract class that implements security interception for secure objects.
 * 
 * <P>
 * The <code>AbstractSecurityInterceptor</code> will ensure the proper startup
 * configuration of the security interceptor. It will also implement the
 * proper handling of secure object invocations, being:
 * 
 * <ol>
 * <li>
 * Extract the {@link SecureContext} from the {@link ContextHolder}, handling
 * any errors such as invalid or <code>null</code> objects.
 * </li>
 * <li>
 * Obtain the {@link Authentication} object from the extracted
 * <code>SecureContext</code>.
 * </li>
 * <li>
 * Determine if the request relates to a secured or public invocation by
 * looking up the secure object request against the {@link
 * ObjectDefinitionSource}.
 * </li>
 * <li>
 * For an invocation that is secured (there is a
 * <code>ConfigAttributeDefinition</code> for the secure object invocation):
 * 
 * <ol>
 * <li>
 * Authenticate the request against the configured {@link
 * AuthenticationManager}, replacing the <code>Authentication</code> object on
 * the <code>ContextHolder</code> with the returned value.
 * </li>
 * <li>
 * Authorize the request against the configured {@link AccessDecisionManager}.
 * </li>
 * <li>
 * Perform any run-as replacement via the configured {@link RunAsManager}.
 * </li>
 * <li>
 * Perform a callback to the {@link SecurityInterceptorCallback}, which will
 * actually proceed with executing the object.
 * </li>
 * <li>
 * If the <code>RunAsManager</code> replaced the <code>Authentication</code>
 * object, return the <code>ContextHolder</code> to the object that existed
 * after the call to <code>AuthenticationManager</code>.
 * </li>
 * </ol>
 * 
 * </li>
 * <li>
 * For an invocation that is public (there is no
 * <code>ConfigAttributeDefinition</code> for the secure object invocation):
 * 
 * <ol>
 * <li>
 * If the <code>ContextHolder</code> contains a <code>SecureContext</code>, set
 * the <code>isAuthenticated</code> flag on the <code>Authentication</code>
 * object to false.
 * </li>
 * <li>
 * Perform a callback to the {@link SecurityInterceptorCallback}, which will
 * actually proceed with the invocation.
 * </li>
 * </ol>
 * 
 * </li>
 * <li>
 * Return the result from the <code>SecurityInterceptorCallback</code> to the
 * method that called {@link AbstractSecurityInterceptor#interceptor(Object,
 * SecurityInterceptorCallback)}. This is almost always a concrete subclass of
 * the <code>AbstractSecurityInterceptor</code>.
 * </li>
 * </ol>
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractSecurityInterceptor implements InitializingBean {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(AbstractSecurityInterceptor.class);

    //~ Instance fields ========================================================

    private AccessDecisionManager accessDecisionManager;
    private AuthenticationManager authenticationManager;
    private RunAsManager runAsManager;
    private boolean validateConfigAttributes = true;

    //~ Methods ================================================================

    public abstract ObjectDefinitionSource obtainObjectDefinitionSource();

    public void setAccessDecisionManager(
        AccessDecisionManager accessDecisionManager) {
        this.accessDecisionManager = accessDecisionManager;
    }

    public AccessDecisionManager getAccessDecisionManager() {
        return accessDecisionManager;
    }

    public void setAuthenticationManager(AuthenticationManager newManager) {
        this.authenticationManager = newManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        return this.authenticationManager;
    }

    public void setRunAsManager(RunAsManager runAsManager) {
        this.runAsManager = runAsManager;
    }

    public RunAsManager getRunAsManager() {
        return runAsManager;
    }

    public void setValidateConfigAttributes(boolean validateConfigAttributes) {
        this.validateConfigAttributes = validateConfigAttributes;
    }

    public boolean isValidateConfigAttributes() {
        return validateConfigAttributes;
    }

    public void afterPropertiesSet() {
        if (this.authenticationManager == null) {
            throw new IllegalArgumentException(
                "An AuthenticationManager is required");
        }

        if (this.accessDecisionManager == null) {
            throw new IllegalArgumentException(
                "An AccessDecisionManager is required");
        }

        if (this.runAsManager == null) {
            throw new IllegalArgumentException("A RunAsManager is required");
        }

        if (this.obtainObjectDefinitionSource() == null) {
            throw new IllegalArgumentException(
                "An ObjectDefinitionSource is required");
        }

        if (this.validateConfigAttributes) {
            Iterator iter = this.obtainObjectDefinitionSource()
                                .getConfigAttributeDefinitions();

            if (iter == null) {
                if (logger.isWarnEnabled()) {
                    logger.warn(
                        "Could not validate configuration attributes as the MethodDefinitionSource did not return a ConfigAttributeDefinition Iterator");
                }

                return;
            }

            Set set = new HashSet();

            while (iter.hasNext()) {
                ConfigAttributeDefinition def = (ConfigAttributeDefinition) iter
                    .next();
                Iterator attributes = def.getConfigAttributes();

                while (attributes.hasNext()) {
                    ConfigAttribute attr = (ConfigAttribute) attributes.next();

                    if (!this.runAsManager.supports(attr)
                        && !this.accessDecisionManager.supports(attr)) {
                        set.add(attr);
                    }
                }
            }

            if (set.size() == 0) {
                if (logger.isInfoEnabled()) {
                    logger.info("Validated configuration attributes");
                }
            } else {
                throw new IllegalArgumentException(
                    "Unsupported configuration attributes: " + set.toString());
            }
        }
    }

    /**
     * Does the work of authenticating and authorizing the request.
     * 
     * <P>
     * Throws {@link net.sf.acegisecurity.AcegiSecurityException} and its
     * subclasses.
     * </p>
     *
     * @param object details of a secure object invocation
     * @param callback the object that will complete the target secure object
     *        invocation
     *
     * @return The value that was returned by the
     *         <code>SecurityInterceptorCallback</code>
     *
     * @throws Throwable if any error occurs during the
     *         <code>SecurityInterceptorCallback</code>
     * @throws IllegalArgumentException if a required argument was missing or
     *         invalid
     * @throws AuthenticationCredentialsNotFoundException if the
     *         <code>ContextHolder</code> is not populated with a valid
     *         <code>SecureContext</code>
     */
    public Object interceptor(Object object,
        SecurityInterceptorCallback callback) throws Throwable {
        if (object == null) {
            throw new IllegalArgumentException("Object was null");
        }

        if (callback == null) {
            throw new IllegalArgumentException("Callback was null");
        }

        if (!this.obtainObjectDefinitionSource().supports(object.getClass())) {
            throw new IllegalArgumentException(
                "ObjectDefinitionSource does not support objects of type "
                + object.getClass());
        }

        ConfigAttributeDefinition attr = this.obtainObjectDefinitionSource()
                                             .getAttributes(object);

        if (attr != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Secure object: " + object.toString()
                    + "; ConfigAttributes: " + attr.toString());
            }

            // Ensure ContextHolder presents a populated SecureContext
            if ((ContextHolder.getContext() == null)
                || !(ContextHolder.getContext() instanceof SecureContext)) {
                throw new AuthenticationCredentialsNotFoundException(
                    "A valid SecureContext was not provided in the RequestContext");
            }

            SecureContext context = (SecureContext) ContextHolder.getContext();

            // We check for just the property we're interested in (we do
            // not call Context.validate() like the ContextInterceptor)
            if (context.getAuthentication() == null) {
                throw new AuthenticationCredentialsNotFoundException(
                    "Authentication credentials were not found in the SecureContext");
            }

            // Attempt authentication
            Authentication authenticated = this.authenticationManager
                .authenticate(context.getAuthentication());
            authenticated.setAuthenticated(true);
            logger.debug("Authenticated: " + authenticated.toString());
            context.setAuthentication(authenticated);
            ContextHolder.setContext((Context) context);

            // Attempt authorization
            this.accessDecisionManager.decide(authenticated, object, attr);

            if (logger.isDebugEnabled()) {
                logger.debug("Authorization successful");
            }

            // Attempt to run as a different user
            Authentication runAs = this.runAsManager.buildRunAs(authenticated,
                    object, attr);

            if (runAs == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "RunAsManager did not change Authentication object");
                }

                return callback.proceedWithObject(object);
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Switching to RunAs Authentication: "
                        + runAs.toString());
                }

                context.setAuthentication(runAs);
                ContextHolder.setContext((Context) context);

                Object ret = callback.proceedWithObject(object);

                if (logger.isDebugEnabled()) {
                    logger.debug("Reverting to original Authentication: "
                        + authenticated.toString());
                }

                context.setAuthentication(authenticated);
                ContextHolder.setContext((Context) context);

                return ret;
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Public object - authentication not attempted");
            }

            // Set Authentication object (if it exists) to be unauthenticated
            if ((ContextHolder.getContext() != null)
                && ContextHolder.getContext() instanceof SecureContext) {
                SecureContext context = (SecureContext) ContextHolder
                    .getContext();

                if (context.getAuthentication() != null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "Authentication object detected and tagged as unauthenticated");
                    }

                    Authentication authenticated = context.getAuthentication();
                    authenticated.setAuthenticated(false);
                    context.setAuthentication(authenticated);
                    ContextHolder.setContext((Context) context);
                }
            }

            return callback.proceedWithObject(object);
        }
    }
}
