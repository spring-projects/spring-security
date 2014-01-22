/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.servletapi;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

import javax.servlet.AsyncContext;
import javax.servlet.AsyncListener;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

/**
 * Provides integration with the Servlet 3 APIs in addition to the ones found in {@link HttpServlet25RequestFactory}.
 * The additional methods that are integrated with can be found below:
 *
 * <ul>
 * <li> {@link HttpServletRequest#authenticate(HttpServletResponse)} - Allows the user to determine if they are
 * authenticated and if not send the user to the login page. See
 * {@link #setAuthenticationEntryPoint(AuthenticationEntryPoint)}.</li>
 * <li> {@link HttpServletRequest#login(String, String)} - Allows the user to authenticate using the
 * {@link AuthenticationManager}. See {@link #setAuthenticationManager(AuthenticationManager)}.</li>
 * <li> {@link HttpServletRequest#logout()} - Allows the user to logout using the {@link LogoutHandler}s configured in
 * Spring Security. See {@link #setLogoutHandlers(List)}.</li>
 * <li> {@link AsyncContext#start(Runnable)} - Automatically copy the {@link SecurityContext} from the
 * {@link SecurityContextHolder} found on the Thread that invoked {@link AsyncContext#start(Runnable)} to the Thread
 * that processes the {@link Runnable}.</li>
 * </ul>
 *
 * @author Rob Winch
 *
 * @see SecurityContextHolderAwareRequestFilter
 * @see HttpServlet25RequestFactory
 * @see Servlet3SecurityContextHolderAwareRequestWrapper
 * @see SecurityContextAsyncContext
 */
final class HttpServlet3RequestFactory implements HttpServletRequestFactory {
    private Log logger = LogFactory.getLog(getClass());

    private final String rolePrefix;
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationManager authenticationManager;
    private List<LogoutHandler> logoutHandlers;

    HttpServlet3RequestFactory(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    /**
     * <p>
     * Sets the {@link AuthenticationEntryPoint} used when integrating {@link HttpServletRequest} with Servlet 3 APIs.
     * Specifically, it will be used when {@link HttpServletRequest#authenticate(HttpServletResponse)} is called and the
     * user is not authenticated.
     * </p>
     * <p>
     * If the value is null (default), then the default container behavior will be be retained when invoking
     * {@link HttpServletRequest#authenticate(HttpServletResponse)}.
     * </p>
     * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use when invoking
     * {@link HttpServletRequest#authenticate(HttpServletResponse)} if the user is not authenticated.
     */

    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /**
     * <p>
     * Sets the {@link AuthenticationManager} used when integrating {@link HttpServletRequest} with Servlet 3 APIs.
     * Specifically, it will be used when {@link HttpServletRequest#login(String, String)} is invoked to determine if
     * the user is authenticated.
     * </p>
     * <p>
     * If the value is null (default), then the default container behavior will be retained when invoking
     * {@link HttpServletRequest#login(String, String)}.
     * </p>
     *
     * @param authenticationManager the {@link AuthenticationManager} to use when invoking
     * {@link HttpServletRequest#login(String, String)}
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * <p>
     * Sets the {@link LogoutHandler}s used when integrating with {@link HttpServletRequest} with Servlet 3 APIs.
     * Specifically it will be used when {@link HttpServletRequest#logout()} is invoked in order to log the user out. So
     * long as the {@link LogoutHandler}s do not commit the {@link HttpServletResponse} (expected), then the user is in
     * charge of handling the response.
     * </p>
     * <p>
     * If the value is null (default), the default container behavior will be retained when invoking
     * {@link HttpServletRequest#logout()}.
     * </p>
     *
     * @param logoutHandlers the {@link List<LogoutHandler>}s when invoking {@link HttpServletRequest#logout()}.
     */
    public void setLogoutHandlers(List<LogoutHandler> logoutHandlers) {
        this.logoutHandlers = logoutHandlers;
    }

    /**
     * Sets the {@link AuthenticationTrustResolver} to be used. The default is
     * {@link AuthenticationTrustResolverImpl}.
     *
     * @param trustResolver
     *            the {@link AuthenticationTrustResolver} to use. Cannot be
     *            null.
     */
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        Assert.notNull(trustResolver, "trustResolver cannot be null");
        this.trustResolver = trustResolver;
    }


    public HttpServletRequest create(HttpServletRequest request, HttpServletResponse response) {
         return new Servlet3SecurityContextHolderAwareRequestWrapper(request, rolePrefix, response);
    }

    private class Servlet3SecurityContextHolderAwareRequestWrapper extends SecurityContextHolderAwareRequestWrapper {
        private final HttpServletResponse response;

        public Servlet3SecurityContextHolderAwareRequestWrapper(HttpServletRequest request, String rolePrefix, HttpServletResponse response) {
            super(request, trustResolver, rolePrefix);
            this.response = response;
        }

        public AsyncContext getAsyncContext() {
            AsyncContext asyncContext = super.getAsyncContext();
            return new SecurityContextAsyncContext(asyncContext);
        }

        public AsyncContext startAsync() {
            AsyncContext startAsync = super.startAsync();
            return new SecurityContextAsyncContext(startAsync);
        }

        public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
                throws IllegalStateException {
            AsyncContext startAsync = super.startAsync(servletRequest, servletResponse);
            return new SecurityContextAsyncContext(startAsync);
        }

        public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
            AuthenticationEntryPoint entryPoint = authenticationEntryPoint;
            if(entryPoint == null) {
                logger.debug("authenticationEntryPoint is null, so allowing original HttpServletRequest to handle authenticate");
                return super.authenticate(response);
            }
            if(isAuthenticated()) {
                return true;
            }
            entryPoint.commence(this, response, new AuthenticationCredentialsNotFoundException("User is not Authenticated"));
            return false;
        }

        public void login(String username, String password) throws ServletException {
            if(isAuthenticated()) {
                throw new ServletException("Cannot perform login for '"
                        + username + "' already authenticated as '"
                        + getRemoteUser() + "'");
            }
            AuthenticationManager authManager = authenticationManager;
            if(authManager == null) {
                logger.debug("authenticationManager is null, so allowing original HttpServletRequest to handle login");
                super.login(username, password);
                return;
            }
            Authentication authentication;
            try {
                authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
            } catch(AuthenticationException loginFailed) {
                SecurityContextHolder.clearContext();
                throw new ServletException(loginFailed.getMessage(), loginFailed);
            }
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        public void logout() throws ServletException {
            List<LogoutHandler> handlers = logoutHandlers;
            if(handlers == null) {
                logger.debug("logoutHandlers is null, so allowing original HttpServletRequest to handle logout");
                super.logout();
                return;
            }
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            for(LogoutHandler logoutHandler : handlers) {
                logoutHandler.logout(this, response, authentication);
            }
        }

        private boolean isAuthenticated() {
            Principal userPrincipal = getUserPrincipal();
            return userPrincipal != null;
        }
    }

    private static class SecurityContextAsyncContext implements AsyncContext {
        private final AsyncContext asyncContext;

        public SecurityContextAsyncContext(AsyncContext asyncContext) {
            this.asyncContext = asyncContext;
        }

        public ServletRequest getRequest() {
            return asyncContext.getRequest();
        }

        public ServletResponse getResponse() {
            return asyncContext.getResponse();
        }

        public boolean hasOriginalRequestAndResponse() {
            return asyncContext.hasOriginalRequestAndResponse();
        }

        public void dispatch() {
            asyncContext.dispatch();
        }

        public void dispatch(String path) {
            asyncContext.dispatch(path);
        }

        public void dispatch(ServletContext context, String path) {
            asyncContext.dispatch(context, path);
        }

        public void complete() {
            asyncContext.complete();
        }

        public void start(Runnable run) {
            asyncContext.start(new DelegatingSecurityContextRunnable(run));
        }

        public void addListener(AsyncListener listener) {
            asyncContext.addListener(listener);
        }

        public void addListener(AsyncListener listener, ServletRequest request, ServletResponse response) {
            asyncContext.addListener(listener, request, response);
        }

        public <T extends AsyncListener> T createListener(Class<T> clazz) throws ServletException {
            return asyncContext.createListener(clazz);
        }

        public long getTimeout() {
            return asyncContext.getTimeout();
        }

        public void setTimeout(long timeout) {
            asyncContext.setTimeout(timeout);
        }
    }
}
