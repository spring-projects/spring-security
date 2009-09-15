package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.jsp.JspException;

import org.springframework.context.ApplicationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionHandler;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * Expression-based access control tag.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class AuthorizeTag extends LegacyAuthorizeTag {
    private String access;

    // If access expression evaluates to "true" return
    public int doStartTag() throws JspException {
        if (access == null || access.length() == 0) {
            return super.doStartTag();
        }

        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (currentUser == null) {
            return SKIP_BODY;
        }

        // Get web expression
        WebSecurityExpressionHandler handler = getExpressionHandler();

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

    public void setAccess(String access) {
        this.access = access;
    }

    WebSecurityExpressionHandler getExpressionHandler() throws JspException {
        ServletContext servletContext = pageContext.getServletContext();
        ApplicationContext ctx = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
        Map<String, WebSecurityExpressionHandler> expressionHdlrs = ctx.getBeansOfType(WebSecurityExpressionHandler.class);

        if (expressionHdlrs.size() == 0) {
            throw new JspException("No visible WebSecurityExpressionHandler instance could be found in the application " +
                    "context. There must be at least one in order to use expressions with taglib support.");
        }

        return (WebSecurityExpressionHandler) expressionHdlrs.values().toArray()[0];
    }

    private static final FilterChain DUMMY_CHAIN = new FilterChain() {
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
           throw new UnsupportedOperationException();
        }
    };
}
