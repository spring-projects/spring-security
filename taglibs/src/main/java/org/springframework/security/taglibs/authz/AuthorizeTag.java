package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.util.*;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;

import org.springframework.context.ApplicationContext;
import org.springframework.core.GenericTypeResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * Access control tag which evaluates its body based either on
 * <ul>
 * <li>an access expression (the "access" attribute), or</li>
 * <li>by evaluating the current user's right to access a particular URL (set using the "url" attribute).</li>
 * </ul>
 * @author Luke Taylor
 * @since 3.0
 */
public class AuthorizeTag extends LegacyAuthorizeTag {
    private String access;
    private String url;
    private String method;
    private String var;

    // If access expression evaluates to "true" return
    public int doStartTag() throws JspException {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (currentUser == null) {
            return SKIP_BODY;
        }

        int result;

        if (access != null && access.length() > 0) {
            result = authorizeUsingAccessExpression(currentUser);
        } else if (url != null && url.length() > 0) {
            result = authorizeUsingUrlCheck(currentUser);
        } else {
            result = super.doStartTag();
        }

        if (var != null) {
            pageContext.setAttribute(var, Boolean.valueOf(result == EVAL_BODY_INCLUDE), PageContext.PAGE_SCOPE);
        }

        return result;
    }

    private int authorizeUsingAccessExpression(Authentication currentUser) throws JspException {
        SecurityExpressionHandler<FilterInvocation> handler = getExpressionHandler();

        Expression accessExpression;
        try {
            accessExpression = handler.getExpressionParser().parseExpression(access);

        } catch (ParseException e) {
            throw new JspException(e);
        }

        FilterInvocation f = new FilterInvocation(pageContext.getRequest(), pageContext.getResponse(), DUMMY_CHAIN);

        if (ExpressionUtils.evaluateAsBoolean(accessExpression, handler.createEvaluationContext(currentUser, f))) {
            return EVAL_BODY_INCLUDE;
        }

        return SKIP_BODY;
    }

    private int authorizeUsingUrlCheck(Authentication currentUser) throws JspException {
        return getPrivilegeEvaluator().isAllowed(((HttpServletRequest)pageContext.getRequest()).getContextPath(),
                url, method, currentUser) ? EVAL_BODY_INCLUDE : SKIP_BODY;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public void setVar(String var) {
        this.var = var;
    }

    SecurityExpressionHandler<FilterInvocation> getExpressionHandler() throws JspException {
        ServletContext servletContext = pageContext.getServletContext();
        ApplicationContext ctx = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
        Map<String, SecurityExpressionHandler> expressionHdlrs = ctx.getBeansOfType(SecurityExpressionHandler.class);


        for (SecurityExpressionHandler h : expressionHdlrs.values()) {
            if (FilterInvocation.class.equals(GenericTypeResolver.resolveTypeArgument(h.getClass(), SecurityExpressionHandler.class))) {
                return h;
            }
        }

        throw new JspException("No visible SecurityExpressionHandler<FilterInvocation> instance could be found in the " +
                "application context. There must be at least one in order to support expressions in JSP 'authorize' tags.");
    }

    WebInvocationPrivilegeEvaluator getPrivilegeEvaluator() throws JspException {
        ServletContext servletContext = pageContext.getServletContext();
        ApplicationContext ctx = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
        Map<String, WebInvocationPrivilegeEvaluator> wipes = ctx.getBeansOfType(WebInvocationPrivilegeEvaluator.class);

        if (wipes.size() == 0) {
            throw new JspException("No visible WebInvocationPrivilegeEvaluator instance could be found in the application " +
                    "context. There must be at least one in order to support the use of URL access checks in 'authorize' tags.");
        }

        return (WebInvocationPrivilegeEvaluator) wipes.values().toArray()[0];
    }

    private static final FilterChain DUMMY_CHAIN = new FilterChain() {
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
           throw new UnsupportedOperationException();
        }
    };
}
