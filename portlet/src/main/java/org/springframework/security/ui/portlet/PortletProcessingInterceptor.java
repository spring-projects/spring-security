/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ui.portlet;

import java.io.IOException;
import java.security.Principal;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.portlet.PortletRequest;
import javax.portlet.PortletResponse;
import javax.portlet.PortletSession;
import javax.portlet.RenderRequest;
import javax.portlet.RenderResponse;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.context.SecurityContext;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.AuthenticationDetailsSource;
import org.springframework.security.ui.AuthenticationDetailsSourceImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.web.portlet.HandlerInterceptor;
import org.springframework.web.portlet.ModelAndView;

/**
 * <p>This interceptor is responsible for processing portlet authentication requests.  This
 * is the portlet equivalent of the <code>AuthenticationProcessingFilter</code> used for
 * traditional servlet-based web applications. It is applied to both <code>ActionRequest</code>s
 * and <code>RenderRequest</code>s alike.  If authentication is successful, the resulting
 * {@link Authentication} object will be placed into the <code>SecurityContext</code>, which
 * is guaranteed to have already been created by an earlier interceptor.  If authentication
 * fails, the <code>AuthenticationException</code> will be placed into the
 * <code>APPLICATION_SCOPE</code> of the <code>PortletSession</code> with the attribute defined
 * by {@link AbstractProcessingFilter#SPRING_SECURITY_LAST_EXCEPTION_KEY}.</p>
 *
 *  <p>Some portals do not properly provide the identity of the current user via the
 * <code>getRemoteUser()</code> or <code>getUserPrincipal()</code> methods of the
 * <code>PortletRequest</code>.  In these cases they sometimes make it available in the
 * <code>USER_INFO</code> map provided as one of the attributes of the request.  If this is
 * the case in your portal, you can specify a list of <code>USER_INFO</code> attributes
 * to check for the username via the <code>userNameAttributes</code> property of this bean.
 * You can also completely override the {@link #getPrincipalFromRequest(PortletRequest)}
 * and {@link #getCredentialsFromRequest(PortletRequest)} methods to suit the particular
 * behavior of your portal.</p>
 *
 * <p>This interceptor will put the <code>PortletRequest</code> object into the
 * <code>details<code> property of the <code>Authentication</code> object that is sent
 * as a request to the <code>AuthenticationManager</code>.  This is done so that the request
 * is available to classes like {@link ContainerPortletAuthoritiesPopulator} that need
 * access to information from the portlet container.  The {@link PortletAuthenticationProvider}
 * will replace this with the <code>USER_INFO</code> map in the resulting <code>Authentication</code>
 * object.</p>
 *
 * @see org.springframework.security.ui.AbstractProcessingFilter
 * @see org.springframework.security.ui.webapp.AuthenticationProcessingFilter
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletProcessingInterceptor implements HandlerInterceptor, InitializingBean {

    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(PortletProcessingInterceptor.class);

    //~ Instance fields ================================================================================================

    private AuthenticationManager authenticationManager;

    private List userNameAttributes;

    private AuthenticationDetailsSource authenticationDetailsSource;

    private boolean useAuthTypeAsCredentials = false;

    public PortletProcessingInterceptor() {
        authenticationDetailsSource = new AuthenticationDetailsSourceImpl();
        ((AuthenticationDetailsSourceImpl)authenticationDetailsSource).setClazz(PortletAuthenticationDetails.class);
    }

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(authenticationManager, "An AuthenticationManager must be set");
    }

    public boolean preHandleAction(ActionRequest request, ActionResponse response,
            Object handler) throws Exception {
        return preHandle(request, response, handler);
    }

    public boolean preHandleRender(RenderRequest request,
            RenderResponse response, Object handler) throws Exception {
        return preHandle(request, response, handler);
    }

    public void postHandleRender(RenderRequest request, RenderResponse response,
            Object handler, ModelAndView modelAndView) throws Exception {
    }

    public void afterActionCompletion(ActionRequest request, ActionResponse response,
            Object handler, Exception ex) throws Exception {
    }

    public void afterRenderCompletion(RenderRequest request, RenderResponse response,
            Object handler, Exception ex) throws Exception {
    }

    /**
     * Common preHandle method for both the action and render phases of the interceptor.
     */
    private boolean preHandle(PortletRequest request, PortletResponse response,
            Object handler) throws Exception {

        // get the SecurityContext
        SecurityContext ctx = SecurityContextHolder.getContext();

        if (logger.isDebugEnabled())
            logger.debug("Checking secure context token: " + ctx.getAuthentication());

        // if there is no existing Authentication object, then lets create one
        if (ctx.getAuthentication() == null) {

            try {

                // build the authentication request from the PortletRequest
                PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(
                        getPrincipalFromRequest(request),
                        getCredentialsFromRequest(request));

                // put the PortletRequest into the authentication request as the "details"
                authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

                if (logger.isDebugEnabled())
                    logger.debug("Beginning authentication request for user '" + authRequest.getName() + "'");

                onPreAuthentication(request, response);

                // ask the authentication manager to authenticate the request
                // it will throw an AuthenticationException if it fails, otherwise it succeeded
                Authentication authResult = authenticationManager.authenticate(authRequest);

                // process a successful authentication
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication success: " + authResult);
                }

                ctx.setAuthentication(authResult);
                onSuccessfulAuthentication(request, response, authResult);

            } catch (AuthenticationException failed) {
                // process an unsuccessful authentication
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication failed - updating ContextHolder to contain null Authentication", failed);
                }
                ctx.setAuthentication(null);
                request.getPortletSession().setAttribute(
                        AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY,
                        failed, PortletSession.APPLICATION_SCOPE);
                onUnsuccessfulAuthentication(request, response, failed);
            }
        }

        return true;
    }

    /**
     * This method attempts to extract a principal from the portlet request.
     * According to the JSR 168 spec, the <code>PortletRequest<code> should return the name
     * of the user in the <code>getRemoteUser()</code> method.  It should also provide a
     * <code>java.security.Principal</code> object from the <code>getUserPrincipal()</code>
     * method.  We will first try these to come up with a valid username.
     * <p>Unfortunately, some portals do not properly return these values for authenticated
     * users.  So, if neither of those succeeds and if the <code>userNameAttributes</code>
     * property has been populated, then we will search through the <code>USER_INFO<code>
     * map from the request to see if we can find a valid username.
     * <p>This method can be overridden by subclasses to provide special handling
     * for portals with weak support for the JSR 168 spec.</p>
     * @param request the portlet request object
     * @return the determined principal object, or null if none found
     */
    protected Object getPrincipalFromRequest(PortletRequest request) {

        // first try getRemoteUser()
        String remoteUser = request.getRemoteUser();
        if (remoteUser != null) {
            return remoteUser;
        }

        // next try getUserPrincipal()
        Principal userPrincipal = request.getUserPrincipal();
        if (userPrincipal != null) {
            String userPrincipalName = userPrincipal.getName();
            if (userPrincipalName != null) {
                return userPrincipalName;
            }
        }

        // last try entries in USER_INFO if any attributes were defined
        if (this.userNameAttributes != null) {
            Map userInfo = null;
            try {
                userInfo = (Map)request.getAttribute(PortletRequest.USER_INFO);
            } catch (Exception e) {
                logger.warn("unable to retrieve USER_INFO map from portlet request", e);
            }
            if (userInfo != null) {
                Iterator i = this.userNameAttributes.iterator();
                while(i.hasNext()) {
                    Object principal = (String)userInfo.get(i.next());
                    if (principal != null) {
                        return principal;
                    }
                }
            }
        }

        // none found so return null
        return null;
    }

    /**
     * This method attempts to extract a credentials from the portlet request.
     * We are trusting the portal framework to authenticate the user, so all
     * we are really doing is trying to put something intelligent in here to
     * indicate the user is authenticated.  According to the JSR 168 spec,
     * PortletRequest.getAuthType() should return a non-null value if the
     * user is authenticated and should be null if not authenticated. So we
     * will use this as the credentials and the token will be trusted as
     * authenticated if the credentials are not null.
     * <p>This method can be overridden by subclasses to provide special handling
     * for portals with weak support for the JSR 168 spec.  If that is done,
     * be sure the value is non-null for authenticated users and null for
     * non-authenticated users.</p>
     * @param request the portlet request object
     * @return the determined credentials object, or null if none found
     */
    protected Object getCredentialsFromRequest(PortletRequest request) {
        if (useAuthTypeAsCredentials) {
            return request.getAuthType();
        }

        return "dummy";
    }

    /**
     * Callback for custom processing prior to the authentication attempt.
     * @param request the portlet request to be authenticated
     * @param response the portlet response to be authenticated
     * @throws AuthenticationException to indicate that authentication attempt is not valid and should be terminated
     * @throws IOException
     */
    protected void onPreAuthentication(PortletRequest request, PortletResponse response)
        throws AuthenticationException, IOException {}

    /**
     * Callback for custom processing after a successful authentication attempt.
     * @param request the portlet request that was authenticated
     * @param response the portlet response that was authenticated
     * @param authResult the resulting Authentication object
     * @throws IOException
     */
    protected void onSuccessfulAuthentication(PortletRequest request, PortletResponse response, Authentication authResult)
        throws IOException {}

    /**
     * Callback for custom processing after an unsuccessful authentication attempt.
     * @param request the portlet request that failed authentication
     * @param response the portlet response that failed authentication
     * @param failed the AuthenticationException that occurred
     * @throws IOException
     */
    protected void onUnsuccessfulAuthentication(PortletRequest request, PortletResponse response, AuthenticationException failed)
        throws IOException {}


    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setUserNameAttributes(List userNameAttributes) {
        this.userNameAttributes = userNameAttributes;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    /**
     * It true, the "authType" proerty of the <tt>PortletRequest</tt> will be used as the credentials.
     * Defaults to false.
     *
     * @param useAuthTypeAsCredentials
     */
    public void setUseAuthTypeAsCredentials(boolean useAuthTypeAsCredentials) {
        this.useAuthTypeAsCredentials = useAuthTypeAsCredentials;
    }
}
