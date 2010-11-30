package org.springframework.security.taglibs.authz;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;

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

            int result = super.authorize() ? Tag.EVAL_BODY_INCLUDE : Tag.SKIP_BODY;

            if (var != null) {
                pageContext.setAttribute(var, Boolean.valueOf(result == EVAL_BODY_INCLUDE), PageContext.PAGE_SCOPE);
            }

            return result;

        } catch (IOException e) {
            throw new JspException(e);
        }
    }

    /**
     * Default processing of the end tag returning EVAL_PAGE.
     *
     * @return EVAL_PAGE
     * @see Tag#doEndTag()
     */
    public int doEndTag() {
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

}
