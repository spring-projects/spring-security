package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.util.*;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;

import org.springframework.expression.BeanResolver;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.OperatorOverloader;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeComparator;
import org.springframework.expression.TypeConverter;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.TypedValue;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.taglibs.TagLibConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.util.ExpressionEvaluationUtils;

/**
 * A JSP {@link Tag} implementation of {@link AbstractAuthorizeTag}.
 *
 * @author Rossen Stoyanchev
 * @see AbstractAuthorizeTag
 * @since 3.1.0
 */
public class JspAuthorizeTag extends AbstractAuthorizeTag implements Tag {

    private Tag parent;

    protected PageContext pageContext;

    protected String id;

    private String var;

    private boolean authorized;

    /**
     * Invokes the base class {@link AbstractAuthorizeTag#authorize()} method to
     * decide if the body of the tag should be skipped or not.
     *
     * @return {@link Tag#SKIP_BODY} or {@link Tag#EVAL_BODY_INCLUDE}
     */
    public int doStartTag() throws JspException {
        try {
            setIfNotGranted(ExpressionEvaluationUtils.evaluateString("ifNotGranted", getIfNotGranted(), pageContext));
            setIfAllGranted(ExpressionEvaluationUtils.evaluateString("ifAllGranted", getIfAllGranted(), pageContext));
            setIfAnyGranted(ExpressionEvaluationUtils.evaluateString("ifAnyGranted", getIfAnyGranted(), pageContext));

            authorized = super.authorize();

            if (!authorized && TagLibConfig.isUiSecurityDisabled()) {
                pageContext.getOut().write(TagLibConfig.getSecuredUiPrefix());
            }

            if (var != null) {
                pageContext.setAttribute(var, authorized, PageContext.PAGE_SCOPE);
            }

            return TagLibConfig.evalOrSkip(authorized);

        } catch (IOException e) {
            throw new JspException(e);
        }
    }

    @Override
    protected EvaluationContext createExpressionEvaluationContext(SecurityExpressionHandler<FilterInvocation> handler) {
        return new PageContextVariableLookupEvaluationContext(super.createExpressionEvaluationContext(handler));
    }

    /**
     * Default processing of the end tag returning EVAL_PAGE.
     *
     * @return EVAL_PAGE
     * @see Tag#doEndTag()
     */
    public int doEndTag() throws JspException {
        try {
            if (!authorized && TagLibConfig.isUiSecurityDisabled()) {
                pageContext.getOut().write(TagLibConfig.getSecuredUiSuffix());
            }
        } catch (IOException e) {
            throw new JspException(e);
        }

        return EVAL_PAGE;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Tag getParent() {
        return parent;
    }

    public void setParent(Tag parent) {
        this.parent = parent;
    }

    public String getVar() {
        return var;
    }

    public void setVar(String var) {
        this.var = var;
    }

    public void release() {
        parent = null;
        id = null;
    }

    public void setPageContext(PageContext pageContext) {
        this.pageContext = pageContext;
    }

    @Override
    protected ServletRequest getRequest() {
        return pageContext.getRequest();
    }

    @Override
    protected ServletResponse getResponse() {
        return pageContext.getResponse();
    }

    @Override
    protected ServletContext getServletContext() {
        return pageContext.getServletContext();
    }

    private final class PageContextVariableLookupEvaluationContext implements EvaluationContext {

        private EvaluationContext delegate;

        private PageContextVariableLookupEvaluationContext(EvaluationContext delegate) {
            this.delegate = delegate;
        }

        public TypedValue getRootObject() {
            return delegate.getRootObject();
        }

        public List<ConstructorResolver> getConstructorResolvers() {
            return delegate.getConstructorResolvers();
        }

        public List<MethodResolver> getMethodResolvers() {
            return delegate.getMethodResolvers();
        }

        public List<PropertyAccessor> getPropertyAccessors() {
            return delegate.getPropertyAccessors();
        }

        public TypeLocator getTypeLocator() {
            return delegate.getTypeLocator();
        }

        public TypeConverter getTypeConverter() {
            return delegate.getTypeConverter();
        }

        public TypeComparator getTypeComparator() {
            return delegate.getTypeComparator();
        }

        public OperatorOverloader getOperatorOverloader() {
            return delegate.getOperatorOverloader();
        }

        public BeanResolver getBeanResolver() {
            return delegate.getBeanResolver();
        }

        public void setVariable(String name, Object value) {
            delegate.setVariable(name, value);
        }

        public Object lookupVariable(String name) {
            Object result = delegate.lookupVariable(name);

            if (result == null) {
                result = pageContext.findAttribute(name);
            }
            return result;
        }
    }

}
