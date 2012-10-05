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

package org.springframework.security.taglibs.velocity;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Enumeration;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.el.ExpressionEvaluator;
import javax.servlet.jsp.el.VariableResolver;
import javax.servlet.jsp.tagext.Tag;

import org.springframework.context.ApplicationContext;
import org.springframework.security.taglibs.authz.AuthenticationTag;
import org.springframework.security.taglibs.authz.LegacyAuthorizeTag;
import org.springframework.util.Assert;


/**
 * I decided to wrap several JSP tag in one class, so I have to using inner class to wrap these JSP tag.  To using
 * this class, you need to inject Spring Context via SetAppCtx() method. AclTag need Spring Context to get AclManger
 * bean.
 */
public class AuthzImpl implements Authz {
    //~ Static fields/initializers =====================================================================================

    private static final ServletContext SPEL_DISABLED_SERVLET_CONTEXT = (ServletContext) Proxy.newProxyInstance(AuthzImpl.class.getClassLoader(), new Class[] {ServletContext.class}, new DisabledSpringJspExpressionSupportActiveServletContext());
    private static final PageContext SPEL_DISABLED_PAGE_CONTEXT = new PageContextAdapter(SPEL_DISABLED_SERVLET_CONTEXT);

    static final int ALL_GRANTED = 1;
    static final int ANY_GRANTED = 2;
    static final int NONE_GRANTED = 3;

    //~ Instance fields ================================================================================================

    private ApplicationContext appCtx;

    //~ Methods ========================================================================================================

    public boolean allGranted(String roles) {
        return ifGranted(roles, ALL_GRANTED);
    }

    public boolean anyGranted(String roles) {
        return ifGranted(roles, ANY_GRANTED);
    }

    public ApplicationContext getAppCtx() {
        return appCtx;
    }

    /**
     * implementation of AuthenticationTag
     */
    public String getPrincipal() {
        MyAuthenticationTag authenticationTag = new MyAuthenticationTag();

        authenticationTag.setProperty("name");

        try {
            authenticationTag.doEndTag();
        } catch (JspException je) {
            je.printStackTrace();
            throw new IllegalArgumentException(je.getMessage());
        }

        return authenticationTag.getLastMessage();
    }

    /**
     * implementation of LegacyAuthorizeTag
     */
    private boolean ifGranted(String roles, int grantType) {
        LegacyAuthorizeTag authorizeTag = new LegacyAuthorizeTag();
        authorizeTag.setPageContext(getPageContext());

        int result = -1;

        try {
            switch (grantType) {
            case ALL_GRANTED:
                authorizeTag.setIfAllGranted(roles);

                break;

            case ANY_GRANTED:
                authorizeTag.setIfAnyGranted(roles);

                break;

            case NONE_GRANTED:
                authorizeTag.setIfNotGranted(roles);

                break;

            default:
                throw new IllegalArgumentException("invalid granted type : " + grantType + " role=" + roles);
            }

            result = authorizeTag.doStartTag();
        } catch (JspException je) {
            throw new IllegalArgumentException(je.getMessage());
        }

        if (Tag.EVAL_BODY_INCLUDE == result) {
            return true;
        } else {
            return false;
        }
    }

    public boolean noneGranted(String roles) {
        return ifGranted(roles, NONE_GRANTED);
    }

    /**
     * test case can use this class to mock application context with aclManager bean in it.
     */
    public void setAppCtx(ApplicationContext appCtx) {
        this.appCtx = appCtx;
    }

    private PageContext getPageContext() {
        return SPEL_DISABLED_PAGE_CONTEXT;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * it must output somthing to JSP page, so have to override the writeMessage method to avoid JSP related
     * operation. Get Idea from Acegi Test class.
     */
    private class MyAuthenticationTag extends AuthenticationTag {
        private static final long serialVersionUID = -1094246833893599161L;
        String lastMessage = null;

        public String getLastMessage() {
            return lastMessage;
        }

        protected void writeMessage(String msg) throws JspException {
            lastMessage = msg;
        }
    }

    private static final class DisabledSpringJspExpressionSupportActiveServletContext implements InvocationHandler {
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if("getInitParameter".equals(method.getName())) {
                return Boolean.FALSE.toString();
            }
            return null;
        }
    }

    private static final class PageContextAdapter extends PageContext {

        private final ServletContext servletContext;

        public PageContextAdapter(ServletContext servletContext) {
            Assert.notNull(servletContext, "servletContext cannot be null");
            this.servletContext = servletContext;
        }

        public void setAttribute(String arg0, Object arg1, int arg2) {
            throw new UnsupportedOperationException();
        }

        public void setAttribute(String arg0, Object arg1) {
            throw new UnsupportedOperationException();
        }

        public void removeAttribute(String arg0, int arg1) {
            throw new UnsupportedOperationException();
        }

        public void removeAttribute(String arg0) {
            throw new UnsupportedOperationException();
        }

        public VariableResolver getVariableResolver() {
            throw new UnsupportedOperationException();
        }

        public JspWriter getOut() {
            throw new UnsupportedOperationException();
        }

        public ExpressionEvaluator getExpressionEvaluator() {
            throw new UnsupportedOperationException();
        }

        public int getAttributesScope(String arg0) {
            throw new UnsupportedOperationException();
        }

        @SuppressWarnings("rawtypes")
        public Enumeration getAttributeNamesInScope(int arg0) {
            throw new UnsupportedOperationException();
        }

        public Object getAttribute(String arg0, int arg1) {
            throw new UnsupportedOperationException();
        }

        public Object getAttribute(String arg0) {
            throw new UnsupportedOperationException();
        }

        public Object findAttribute(String arg0) {
            throw new UnsupportedOperationException();
        }

        public void release() {
            throw new UnsupportedOperationException();
        }

        public void initialize(Servlet arg0, ServletRequest arg1, ServletResponse arg2, String arg3, boolean arg4,
                int arg5, boolean arg6) throws IOException, IllegalStateException, IllegalArgumentException {
            throw new UnsupportedOperationException();
        }

        public void include(String arg0, boolean arg1) throws ServletException, IOException {
            throw new UnsupportedOperationException();
        }

        public void include(String arg0) throws ServletException, IOException {
            throw new UnsupportedOperationException();
        }

        public void handlePageException(Throwable arg0) throws ServletException, IOException {
            throw new UnsupportedOperationException();
        }

        public void handlePageException(Exception arg0) throws ServletException, IOException {
            throw new UnsupportedOperationException();
        }

        public HttpSession getSession() {
            throw new UnsupportedOperationException();
        }

        public ServletContext getServletContext() {
            return servletContext;
        }

        public ServletConfig getServletConfig() {
            throw new UnsupportedOperationException();
        }

        public ServletResponse getResponse() {
            throw new UnsupportedOperationException();
        }

        public ServletRequest getRequest() {
            throw new UnsupportedOperationException();
        }

        public Object getPage() {
            throw new UnsupportedOperationException();
        }

        public Exception getException() {
            throw new UnsupportedOperationException();
        }

        public void forward(String arg0) throws ServletException, IOException {
            throw new UnsupportedOperationException();
        }
    }
}
