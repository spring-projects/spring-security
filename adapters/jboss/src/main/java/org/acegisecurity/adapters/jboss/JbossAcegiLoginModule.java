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
package net.sf.acegisecurity.adapters.jboss;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

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
 * Adapter to enable JBoss to authenticate via the Acegi Security System for
 * Spring.
 *
 * <p>
 * Returns a {@link PrincipalAcegiUserToken} to JBoss' authentication system,
 * which is subsequently available from
 * <code>java:comp/env/security/subject</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JbossAcegiLoginModule extends AbstractServerLoginModule {
    private AuthenticationManager authenticationManager;
    private Principal identity;
    private String key;
    private char[] credential;

    public void initialize(Subject subject, CallbackHandler callbackHandler,
        Map sharedState, Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        this.key = (String) options.get("key");

        if ((key == null) || "".equals(key)) {
            throw new IllegalArgumentException("key must be defined");
        }

        String appContextLocation = (String) options.get("appContextLocation");

        if ((appContextLocation == null) || "".equals(appContextLocation)) {
            throw new IllegalArgumentException(
                "appContextLocation must be defined");
        }

        if (Thread.currentThread().getContextClassLoader().getResource(appContextLocation) == null) {
            throw new IllegalArgumentException("Cannot locate " +
                appContextLocation);
        }

        ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext(appContextLocation);
        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new IllegalArgumentException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
        super.log.info("Successfully started JbossSpringLoginModule");
    }

    public boolean login() throws LoginException {
        super.loginOk = false;

        String[] info = getUsernameAndPassword();
        String username = info[0];
        String password = info[1];

        if ((username == null) && (password == null)) {
            identity = null;
            super.log.trace("Authenticating as unauthenticatedIdentity=" +
                identity);
        }

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        if (identity == null) {
            Authentication request = new UsernamePasswordAuthenticationToken(username,
                    password);
            Authentication response = null;

            try {
                response = authenticationManager.authenticate(request);
            } catch (AuthenticationException failed) {
                if (super.log.isDebugEnabled()) {
                    super.log.debug("Bad password for username=" + username);
                }

                throw new FailedLoginException(
                    "Password Incorrect/Password Required");
            }

            identity = new PrincipalAcegiUserToken(this.key,
                    response.getPrincipal().toString(),
                    response.getCredentials().toString(),
                    response.getAuthorities());
        }

        if (getUseFirstPass() == true) {
            // Add the username and password to the shared state map
            sharedState.put("javax.security.auth.login.name", username);
            sharedState.put("javax.security.auth.login.password", credential);
        }

        super.loginOk = true;
        super.log.trace("User '" + identity + "' authenticated, loginOk=" +
            loginOk);

        return true;
    }

    protected Principal getIdentity() {
        return this.identity;
    }

    protected Group[] getRoleSets() throws LoginException {
        SimpleGroup roles = new SimpleGroup("Roles");
        Group[] roleSets = { roles };

        if (this.identity instanceof Authentication) {
            Authentication user = (Authentication) this.identity;

            for (int i = 0; i < user.getAuthorities().length; i++) {
                roles.addMember(new SimplePrincipal(
                        user.getAuthorities()[i].getAuthority()));
            }
        }

        return roleSets;
    }

    protected String[] getUsernameAndPassword() throws LoginException {
        String[] info = { null, null };

        // prompt for a username and password
        if (callbackHandler == null) {
            throw new LoginException("Error: no CallbackHandler available " +
                "to collect authentication information");
        }

        NameCallback nc = new NameCallback("User name: ", "guest");
        PasswordCallback pc = new PasswordCallback("Password: ", false);
        Callback[] callbacks = { nc, pc };
        String username = null;
        String password = null;

        try {
            callbackHandler.handle(callbacks);
            username = nc.getName();

            char[] tmpPassword = pc.getPassword();

            if (tmpPassword != null) {
                credential = new char[tmpPassword.length];
                System.arraycopy(tmpPassword, 0, credential, 0,
                    tmpPassword.length);
                pc.clearPassword();
                password = new String(credential);
            }
        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("CallbackHandler does not support: " +
                uce.getCallback());
        }

        info[0] = username;
        info[1] = password;

        return info;
    }
}
