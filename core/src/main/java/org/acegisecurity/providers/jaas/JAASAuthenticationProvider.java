package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.providers.jaas.event.JAASAuthenticationFailedEvent;
import net.sf.acegisecurity.providers.jaas.event.JAASAuthenticationSuccessEvent;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationServiceException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.providers.jaas.AuthorityGranter;
import net.sf.acegisecurity.providers.jaas.JAASAuthenticationCallbackHandler;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationContextException;
import org.springframework.core.io.Resource;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 15, 2004<br>
 */
public class JAASAuthenticationProvider implements AuthenticationProvider, InitializingBean, ApplicationContextAware {

    private ApplicationContext context;
    private String loginContextName = "ACEGI";
    private Resource loginConfig;
    private JAASAuthenticationCallbackHandler[] callbackHandlers;
    private AuthorityGranter[] authorityGranters;

    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        if (auth instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) auth;

            try {

                LoginContext lc = new LoginContext(loginContextName, new InternalCallbackHandler(auth));
                lc.login();

                Set authorities = new HashSet();

                if (token.getAuthorities() != null) {
                    authorities.addAll(Arrays.asList(token.getAuthorities()));
                }

                Subject subject = lc.getSubject();


                Set principals = subject.getPrincipals();
                for (Iterator iterator = principals.iterator(); iterator.hasNext();) {
                    Principal principal = (Principal) iterator.next();
                    for (int i = 0; i < authorityGranters.length; i++) {
                        AuthorityGranter granter = authorityGranters[i];
                        String role = granter.grant(principal);
                        if (role != null) {
                            authorities.add(new JAASGrantedAuthority(role, principal));
                        }
                    }
                }

                token.setAuthorities((GrantedAuthority[]) authorities.toArray(new GrantedAuthority[authorities.size()]));

                context.publishEvent(new JAASAuthenticationSuccessEvent(token));

                return token;

            } catch (LoginException e) {
                context.publishEvent(new JAASAuthenticationFailedEvent(auth, e));
                throw new AuthenticationServiceException(e.toString());
            }
        }
        return null;
    }

    public boolean supports(Class aClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.context = applicationContext;
    }

    public String getLoginContextName() {
        return loginContextName;
    }

    public void setLoginContextName(String loginContextName) {
        this.loginContextName = loginContextName;
    }

    public Resource getLoginConfig() {
        return loginConfig;
    }

    public void setLoginConfig(Resource loginConfig) throws IOException {
        this.loginConfig = loginConfig;
    }

    public void afterPropertiesSet() throws Exception {

        if (loginConfig == null)
            throw new ApplicationContextException("loginConfig must be set on " + getClass());

        if (loginContextName == null)
            throw new ApplicationContextException("loginContextName must be set on " + getClass());

        int n = 1;
        while (Security.getProperty("login.config.url." + n) != null) n++;

        Security.setProperty("login.config.url." + n, loginConfig.getURL().toString());
    }

    public JAASAuthenticationCallbackHandler[] getCallbackHandlers() {
        return callbackHandlers;
    }

    public void setCallbackHandlers(JAASAuthenticationCallbackHandler[] callbackHandlers) {
        this.callbackHandlers = callbackHandlers;
    }

    public AuthorityGranter[] getAuthorityGranters() {
        return authorityGranters;
    }

    public void setAuthorityGranters(AuthorityGranter[] authorityGranters) {
        this.authorityGranters = authorityGranters;
    }

    private class InternalCallbackHandler implements CallbackHandler {

        private Authentication authentication;

        public InternalCallbackHandler(Authentication authentication) {
            this.authentication = authentication;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

            for (int i = 0; i < callbackHandlers.length; i++) {
                JAASAuthenticationCallbackHandler handler = callbackHandlers[i];
                handler.setAuthentication(authentication);
                for (int j = 0; j < callbacks.length; j++) {
                    Callback callback = callbacks[j];
                    handler.handle(callback);
                }
            }
        }
    }
}
