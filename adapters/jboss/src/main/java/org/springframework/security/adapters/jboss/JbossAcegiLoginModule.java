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

package org.springframework.security.adapters.jboss;

import org.springframework.security.AccountExpiredException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.CredentialsExpiredException;

import org.springframework.security.adapters.PrincipalAcegiUserToken;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

import org.springframework.beans.factory.access.BeanFactoryLocator;
import org.springframework.beans.factory.access.BeanFactoryReference;
import org.springframework.beans.factory.access.SingletonBeanFactoryLocator;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.security.Principal;
import java.security.acl.Group;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;


/**
 * Adapter to enable JBoss to authenticate via the Acegi Security System for Spring.<p>Returns a {@link
 * PrincipalAcegiUserToken} to JBoss' authentication system, which is subsequently available from
 * <code>java:comp/env/security/subject</code>.</p>
 *
 * @author Ben Alex
 * @author Sergio Bern�
 * @version $Id$
 */
public class JbossAcegiLoginModule extends AbstractServerLoginModule {
    //~ Instance fields ================================================================================================

    private AuthenticationManager authenticationManager;
    private Principal identity;
    private String key;
    private char[] credential;

    //~ Methods ========================================================================================================

    protected Principal getIdentity() {
        return this.identity;
    }

    protected Group[] getRoleSets() throws LoginException {
        SimpleGroup roles = new SimpleGroup("Roles");
        Group[] roleSets = {roles};

        if (this.identity instanceof Authentication) {
            Authentication user = (Authentication) this.identity;

            for (int i = 0; i < user.getAuthorities().length; i++) {
                roles.addMember(new SimplePrincipal(user.getAuthorities()[i].getAuthority()));
            }
        }

        return roleSets;
    }

    protected String[] getUsernameAndPassword() throws LoginException {
        String[] info = {null, null};

        // prompt for a username and password
        if (callbackHandler == null) {
            throw new LoginException("Error: no CallbackHandler available " + "to collect authentication information");
        }

        NameCallback nc = new NameCallback("User name: ", "guest");
        PasswordCallback pc = new PasswordCallback("Password: ", false);
        Callback[] callbacks = {nc, pc};
        String username = null;
        String password = null;

        try {
            callbackHandler.handle(callbacks);
            username = nc.getName();

            char[] tmpPassword = pc.getPassword();

            if (tmpPassword != null) {
                credential = new char[tmpPassword.length];
                System.arraycopy(tmpPassword, 0, credential, 0, tmpPassword.length);
                pc.clearPassword();
                password = new String(credential);
            }
        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("CallbackHandler does not support: " + uce.getCallback());
        }

        info[0] = username;
        info[1] = password;

        return info;
    }

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        if (super.log.isInfoEnabled()) {
            super.log.info("initializing jboss login module");
        }

        this.key = (String) options.get("key");

        if ((key == null) || "".equals(key)) {
            throw new IllegalArgumentException("key must be defined");
        }

        String singletonId = (String) options.get("singletonId");

        String appContextLocation = (String) options.get("appContextLocation");

        if ((((singletonId == null) || "".equals(singletonId)) && (appContextLocation == null))
            || "".equals(appContextLocation)) {
            throw new IllegalArgumentException("appContextLocation must be defined");
        }

        String beanName = (String) options.get("authenticationManager");

        // Attempt to find the appContextLocation only if no singletonId was defined
        if ((singletonId == null) || "".equals(singletonId)) {
            if (Thread.currentThread().getContextClassLoader().getResource(appContextLocation) == null) {
                if (super.log.isInfoEnabled()) {
                    super.log.info("cannot locate " + appContextLocation);
                }

                throw new IllegalArgumentException("Cannot locate " + appContextLocation);
            }
        }

        ApplicationContext ctx = null;

        if ((singletonId == null) || "".equals(singletonId)) {
            try {
                ctx = new ClassPathXmlApplicationContext(appContextLocation);
            } catch (Exception e) {
                if (super.log.isInfoEnabled()) {
                    super.log.info("error loading spring context " + appContextLocation + " " + e);
                }

                throw new IllegalArgumentException("error loading spring context " + appContextLocation + " " + e);
            }
        } else {
            if (super.log.isInfoEnabled()) {
                super.log.debug("retrieving singleton instance " + singletonId);
            }

            BeanFactoryLocator bfl = SingletonBeanFactoryLocator.getInstance();
            BeanFactoryReference bf = bfl.useBeanFactory(singletonId);
            ctx = (ApplicationContext) bf.getFactory();

            if (ctx == null) {
                if (super.log.isInfoEnabled()) {
                    super.log.info("singleton " + beanName + " does not exists");
                }

                throw new IllegalArgumentException("singleton " + singletonId + " does not exists");
            }
        }

        if ((beanName == null) || "".equals(beanName)) {
            Map beans = null;

            try {
                beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);
            } catch (Exception e) {
                if (super.log.isInfoEnabled()) {
                    super.log.info("exception in getBeansOfType " + e);
                }

                throw new IllegalStateException("spring error in get beans by class");
            }

            if (beans.size() == 0) {
                throw new IllegalArgumentException(
                    "Bean context must contain at least one bean of type AuthenticationManager");
            }

            beanName = (String) beans.keySet().iterator().next();
        }

        authenticationManager = (AuthenticationManager) ctx.getBean(beanName);

        if (super.log.isInfoEnabled()) {
            super.log.info("Successfully started JbossSpringLoginModule");
        }
    }

    public boolean login() throws LoginException {
        super.loginOk = false;

        String[] info = getUsernameAndPassword();
        String username = info[0];
        String password = info[1];

        if ((username == null) && (password == null)) {
            identity = null;
            super.log.trace("Authenticating as unauthenticatedIdentity=" + identity);
        }

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        if (super.log.isDebugEnabled()) {
            super.log.debug("checking identity");
        }

        if (identity == null) {
            super.log.debug("creating usernamepassword token");

            Authentication request = new UsernamePasswordAuthenticationToken(username, password);
            Authentication response = null;

            try {
                if (super.log.isDebugEnabled()) {
                    super.log.debug("attempting authentication");
                }

                response = authenticationManager.authenticate(request);

                if (super.log.isDebugEnabled()) {
                    super.log.debug("authentication succeded");
                }
            } catch (CredentialsExpiredException cee) {
                if (super.log.isDebugEnabled()) {
                    super.log.debug("Credential has expired");
                }

                throw new javax.security.auth.login.CredentialExpiredException(
                    "The credential used to identify the user has expired");
            } catch (AccountExpiredException cee) {
                if (super.log.isDebugEnabled()) {
                    super.log.debug("Account has expired, throwing jaas exception");
                }

                throw new javax.security.auth.login.AccountExpiredException(
                    "The account specified in login has expired");
            } catch (AuthenticationException failed) {
                if (super.log.isDebugEnabled()) {
                    super.log.debug("Bad password for username=" + username);
                }

                throw new FailedLoginException("Password Incorrect/Password Required");
            }

            super.log.debug("user is logged. redirecting to jaas classes");

            identity = new PrincipalAcegiUserToken(this.key, response.getName(), response.getCredentials().toString(),
                    response.getAuthorities(), response.getPrincipal());
        }

        if (getUseFirstPass() == true) {
            // Add the username and password to the shared state map
            sharedState.put("javax.security.auth.login.name", username);
            sharedState.put("javax.security.auth.login.password", credential);
        }

        super.loginOk = true;
        super.log.trace("User '" + identity + "' authenticated, loginOk=" + loginOk);

        return true;
    }
}
