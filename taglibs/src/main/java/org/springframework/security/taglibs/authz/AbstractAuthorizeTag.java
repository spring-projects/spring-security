/*
 * Copyright 2004-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.core.GenericTypeResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.support.SecurityWebApplicationContextUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * A base class for an &lt;authorize&gt; tag that is independent of the tag rendering technology (JSP, Facelets).
 * It treats tag attributes as simple strings rather than strings that may contain expressions with the
 * exception of the "access" attribute, which is always expected to contain a Spring EL expression.
 * <p/>
 * Subclasses are expected to extract tag attribute values from the specific rendering technology, evaluate
 * them as expressions if necessary, and set the String-based attributes of this class.
 *
 * @author Francois Beausoleil
 * @author Luke Taylor
 * @author Rossen Stoyanchev
 * @author Rob Winch
 * @since 3.1.0
 */
public abstract class AbstractAuthorizeTag {
    private String access;
    private String url;
    private String method = "GET";
    private String ifAllGranted;
    private String ifAnyGranted;
    private String ifNotGranted;

    /**
     * This method allows subclasses to provide a way to access the ServletRequest according to the rendering
     * technology.
     */
    protected abstract ServletRequest getRequest();

    /**
     * This method allows subclasses to provide a way to access the ServletResponse according to the rendering
     * technology.
     */
    protected abstract ServletResponse getResponse();

    /**
     * This method allows subclasses to provide a way to access the ServletContext according to the rendering
     * technology.
     */
    protected abstract ServletContext getServletContext();

    /**
     * Make an authorization decision by considering all &lt;authorize&gt; tag attributes. The following are valid
     * combinations of attributes:
     * <ul>
     * <li>access</li>
     * <li>url, method</li>
     * <li>ifAllGranted, ifAnyGranted, ifNotGranted</li>
     * </ul>
     * The above combinations are mutually exclusive and evaluated in the given order.
     *
     * @return the result of the authorization decision
     * @throws IOException
     */
    public boolean authorize() throws IOException {
        boolean isAuthorized;

        if (StringUtils.hasText(getAccess())) {
            isAuthorized = authorizeUsingAccessExpression();

        } else if (StringUtils.hasText(getUrl())) {
            isAuthorized = authorizeUsingUrlCheck();

        } else {
            isAuthorized = authorizeUsingGrantedAuthorities();

        }

        return isAuthorized;
    }

    /**
     * Make an authorization decision by considering ifAllGranted, ifAnyGranted, and ifNotGranted. All 3 or any
     * combination can be provided. All provided attributes must evaluate to true.
     *
     * @return the result of the authorization decision
     */
    public boolean authorizeUsingGrantedAuthorities() {
        boolean hasTextAllGranted = StringUtils.hasText(getIfAllGranted());
        boolean hasTextAnyGranted = StringUtils.hasText(getIfAnyGranted());
        boolean hasTextNotGranted = StringUtils.hasText(getIfNotGranted());

        if ((!hasTextAllGranted) && (!hasTextAnyGranted) && (!hasTextNotGranted)) {
            return false;
        }

        final Collection<? extends GrantedAuthority> granted = getPrincipalAuthorities();
        final Set<String> grantedRoles = authoritiesToRoles(granted);

        if (hasTextAllGranted) {
            final Set<String> requiredRoles = splitRoles(getIfAllGranted());
            if (!grantedRoles.containsAll(requiredRoles)) {
                return false;
            }
        }

        if (hasTextAnyGranted) {
            final Set<String> expectOneOfRoles = splitRoles(getIfAnyGranted());
            if (!containsAnyValue(grantedRoles, expectOneOfRoles)) {
                return false;
            }
        }

        if (hasTextNotGranted) {
            final Set<String> expectNoneOfRoles = splitRoles(getIfNotGranted());
            if (containsAnyValue(expectNoneOfRoles, grantedRoles)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Make an authorization decision based on a Spring EL expression. See the "Expression-Based Access Control" chapter
     * in Spring Security for details on what expressions can be used.
     *
     * @return the result of the authorization decision
     * @throws IOException
     */
    public boolean authorizeUsingAccessExpression() throws IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return false;
        }

        SecurityExpressionHandler<FilterInvocation> handler = getExpressionHandler();

        Expression accessExpression;
        try {
            accessExpression = handler.getExpressionParser().parseExpression(getAccess());

        } catch (ParseException e) {
            IOException ioException = new IOException();
            ioException.initCause(e);
            throw ioException;
        }

        return ExpressionUtils.evaluateAsBoolean(accessExpression, createExpressionEvaluationContext(handler));
    }

    /**
     * Allows the {@code EvaluationContext} to be customized for variable lookup etc.
     */
    protected EvaluationContext createExpressionEvaluationContext(SecurityExpressionHandler<FilterInvocation> handler) {
        FilterInvocation f = new FilterInvocation(getRequest(), getResponse(), new FilterChain() {
            public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
                throw new UnsupportedOperationException();
            }
        });

        return handler.createEvaluationContext(SecurityContextHolder.getContext().getAuthentication(), f);
    }

    /**
     * Make an authorization decision based on the URL and HTTP method attributes. True is returned if the user is
     * allowed to access the given URL as defined.
     *
     * @return the result of the authorization decision
     * @throws IOException
     */
    public boolean authorizeUsingUrlCheck() throws IOException {
        String contextPath = ((HttpServletRequest) getRequest()).getContextPath();
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        return getPrivilegeEvaluator().isAllowed(contextPath, getUrl(), getMethod(), currentUser);
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = (method != null) ? method.toUpperCase() : null;
    }

    public String getIfAllGranted() {
        return ifAllGranted;
    }

    public void setIfAllGranted(String ifAllGranted) {
        this.ifAllGranted = ifAllGranted;
    }

    public String getIfAnyGranted() {
        return ifAnyGranted;
    }

    public void setIfAnyGranted(String ifAnyGranted) {
        this.ifAnyGranted = ifAnyGranted;
    }

    public String getIfNotGranted() {
        return ifNotGranted;
    }

    public void setIfNotGranted(String ifNotGranted) {
        this.ifNotGranted = ifNotGranted;
    }

    /*------------- Private helper methods  -----------------*/

    private Collection<? extends GrantedAuthority> getPrincipalAuthorities() {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        if (null == currentUser) {
            return Collections.emptyList();
        }
        return currentUser.getAuthorities();
    }

    /**
     * Splits the authorityString using "," as a delimiter into a Set.
     * @param authorityString
     * @return
     */
    private Set<String> splitRoles(String authorityString) {
        String[] rolesArray = StringUtils.tokenizeToStringArray(authorityString, ",");
        Set<String> roles = new HashSet<String>(rolesArray.length);
        for(String role : rolesArray) {
            roles.add(role);
        }
        return roles;
    }

    /**
     * Returns true if any of the values are contained in toTest. Otherwise, false.
     * @param toTest Check this Set to see if any of the values are contained in it.
     * @param values The values to check if they are in toTest.
     * @return
     */
    private boolean containsAnyValue(Set<String> toTest, Collection<String> values) {
        for(String value : values) {
            if(toTest.contains(value)) {
                return true;
            }
        }
        return false;
    }

    private Set<String> authoritiesToRoles(Collection<? extends GrantedAuthority> c) {
        Set<String> target = new HashSet<String>();
        for (GrantedAuthority authority : c) {
            if (null == authority.getAuthority()) {
                throw new IllegalArgumentException(
                        "Cannot process GrantedAuthority objects which return null from getAuthority() - attempting to process "
                                + authority.toString());
            }
            target.add(authority.getAuthority());
        }
        return target;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private SecurityExpressionHandler<FilterInvocation> getExpressionHandler() throws IOException {
        ApplicationContext appContext = SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(getServletContext());
        Map<String, SecurityExpressionHandler> handlers = appContext
                .getBeansOfType(SecurityExpressionHandler.class);

        for (SecurityExpressionHandler h : handlers.values()) {
            if (FilterInvocation.class.equals(GenericTypeResolver.resolveTypeArgument(h.getClass(),
                    SecurityExpressionHandler.class))) {
                return h;
            }
        }

        throw new IOException("No visible WebSecurityExpressionHandler instance could be found in the application "
                + "context. There must be at least one in order to support expressions in JSP 'authorize' tags.");
    }

    private WebInvocationPrivilegeEvaluator getPrivilegeEvaluator() throws IOException {
        WebInvocationPrivilegeEvaluator privEvaluatorFromRequest = (WebInvocationPrivilegeEvaluator) getRequest()
                .getAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE);
        if(privEvaluatorFromRequest != null) {
            return privEvaluatorFromRequest;
        }

        ApplicationContext ctx = SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(getServletContext());
        Map<String, WebInvocationPrivilegeEvaluator> wipes = ctx
                .getBeansOfType(WebInvocationPrivilegeEvaluator.class);

        if (wipes.size() == 0) {
            throw new IOException(
                    "No visible WebInvocationPrivilegeEvaluator instance could be found in the application "
                            + "context. There must be at least one in order to support the use of URL access checks in 'authorize' tags.");
        }

        return (WebInvocationPrivilegeEvaluator) wipes.values().toArray()[0];
    }
}
