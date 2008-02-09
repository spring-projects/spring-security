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

import org.springframework.security.acl.AclManager;

import org.springframework.security.taglibs.authz.AclTag;
import org.springframework.security.taglibs.authz.AuthenticationTag;
import org.springframework.security.taglibs.authz.AuthorizeTag;

import org.springframework.context.ApplicationContext;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;


/**
 * I decided to wrap several JSP tag in one class, so I have to using inner class to wrap these JSP tag.  To using
 * this class, you need to inject Spring Context via SetAppCtx() method. AclTag need Spring Context to get AclManger
 * bean.
 */
public class AuthzImpl implements Authz {
    //~ Static fields/initializers =====================================================================================

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
     *
     * @return DOCUMENT ME!
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public String getPrincipal() {
        MyAuthenticationTag authenticationTag = new MyAuthenticationTag();

        authenticationTag.setProperty("username");

        try {
            authenticationTag.doStartTag();
        } catch (JspException je) {
            je.printStackTrace();
            throw new IllegalArgumentException(je.getMessage());
        }

        return authenticationTag.getLastMessage();
    }

    /**
     * implementation of AclTag
     *
     * @param domainObject DOCUMENT ME!
     * @param permissions DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public boolean hasPermission(Object domainObject, String permissions) {
        MyAclTag aclTag = new MyAclTag();
        aclTag.setPageContext(null);
        aclTag.setContext(getAppCtx());
        aclTag.setDomainObject(domainObject);
        aclTag.setHasPermission(permissions);

        int result = -1;

        try {
            result = aclTag.doStartTag();
        } catch (JspException je) {
            throw new IllegalArgumentException(je.getMessage());
        }

        if (Tag.EVAL_BODY_INCLUDE == result) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * implementation of AuthorizeTag
     *
     * @param roles DOCUMENT ME!
     * @param grantType DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    private boolean ifGranted(String roles, int grantType) {
        AuthorizeTag authorizeTag = new AuthorizeTag();

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
     *
     * @param appCtx DOCUMENT ME!
     */
    public void setAppCtx(ApplicationContext appCtx) {
        this.appCtx = appCtx;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * AclTag need to access the application context via the <code> WebApplicationContextUtils</code> and
     * locate an {@link AclManager}. WebApplicationContextUtils get application context via ServletContext. I decided
     * to let the Authz provide the Spring application context.
     */
    private class MyAclTag extends AclTag {
        private static final long serialVersionUID = 6752340622125924108L;
        ApplicationContext context;

        protected ApplicationContext getContext(PageContext pageContext) {
            return context;
        }

        protected void setContext(ApplicationContext context) {
            this.context = context;
        }
    }

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
}
