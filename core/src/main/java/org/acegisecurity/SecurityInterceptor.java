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

package net.sf.acegisecurity;

import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * Intercepts calls to an object and applies security.
 * 
 * <p>
 * A method is treated as public unless it has one or more configuration
 * attributes defined via  {@link
 * #setMethodDefinitionSource(MethodDefinitionSource)}. If public, no
 * authentication will be attempted, which means an unauthenticated {@link
 * Authentication} object may be present in the {@link ContextHolder} (if any
 * such an unauthenticated <code>Authentication</code> object exists, its
 * {@link Authentication#isAuthenticated()} method will  return
 * <code>false</code> once the <code>SecurityInterceptor</code> has
 * intercepted the public method).
 * </p>
 * 
 * <p>
 * For those methods to be secured by the interceptor, one or more
 * configuration attributes must be defined. These attributes are stored as
 * {@link ConfigAttribute} objects.
 * </p>
 * 
 * <p>
 * The presence of a configuration attribute for a given method will force
 * authentication to be attempted via the {@link AuthenticationManager}
 * configured against the interceptor. If successfully authenticated, the
 * configured {@link AccessDecisionManager} will be passed the  {@link
 * ConfigAttributeDefinition} applicable for the method invocation,  the
 * method invocation itself, and the <code>Authentication</code> object. The
 * <code>AccessDecisionManager</code> which will then make the  authorization
 * decision.
 * </p>
 * 
 * <p>
 * There shouldn't be any requirement to customise the behaviour of the
 * <code>SecurityInterceptor</code>, as all security decisions are made by the
 * <code>AuthenticationProvider</code> and <code>AccessDecisionManager</code>
 * interfaces, which can of course be replaced with different concrete
 * implementations.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityInterceptor implements MethodInterceptor, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(SecurityInterceptor.class);

    //~ Instance fields ========================================================

    private AccessDecisionManager accessDecisionManager;
    private AuthenticationManager authenticationManager;
    private MethodDefinitionSource methodDefinitionSource;
    private RunAsManager runAsManager;
    private boolean validateConfigAttributes = true;

    //~ Methods ================================================================

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

    public void setMethodDefinitionSource(MethodDefinitionSource newSource) {
        this.methodDefinitionSource = newSource;
    }

    public MethodDefinitionSource getMethodDefinitionSource() {
        return this.methodDefinitionSource;
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

        if (this.methodDefinitionSource == null) {
            throw new IllegalArgumentException(
                "A MethodDefinitionSource is required");
        }

        if (this.validateConfigAttributes) {
            Iterator iter = this.methodDefinitionSource
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
     * Does the work of authenticating and authorizing the request. Throws
     * {@link AcegiSecurityException} and its subclasses.
     *
     * @param mi The method being invoked which requires a security decision
     *
     * @return The returned value from the method invocation
     *
     * @throws Throwable if any error occurs
     * @throws AuthenticationCredentialsNotFoundException if the
     *         <code>ContextHolder</code> does not contain a valid
     *         <code>SecureContext</code> which in turn contains an
     *         <code>Authentication</code> object
     */
    public Object invoke(MethodInvocation mi) throws Throwable {
        ConfigAttributeDefinition attr = this.methodDefinitionSource
            .getAttributes(mi);

        if (attr != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Secure method configuration "
                    + attr.getConfigAttributes().toString());
            }

            // Ensure ContextHolder presents a populated SecureContext
            if ((ContextHolder.getContext() == null)
                || !(ContextHolder.getContext() instanceof SecureContext)) {
                throw new AuthenticationCredentialsNotFoundException(
                    "A valid SecureContext was not provided in the RequestContext");
            }

            SecureContext context = (SecureContext) ContextHolder.getContext();

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
            this.accessDecisionManager.decide(authenticated, mi, attr);

            if (logger.isDebugEnabled()) {
                logger.debug("Authorization successful");
            }

            // Attempt to run as a different user
            Authentication runAs = this.runAsManager.buildRunAs(authenticated,
                    mi, attr);

            if (runAs == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "RunAsManager did not change Authentication object");
                }

                Object ret = mi.proceed();

                return ret;
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Switching to RunAs Authentication: "
                        + runAs.toString());
                }

                context.setAuthentication(runAs);
                ContextHolder.setContext((Context) context);

                Object ret = mi.proceed();

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
                logger.debug("Public method - authentication not attempted");
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

            Object ret = mi.proceed();

            return ret;
        }
    }
}
