/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.taglibs.authz;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.acl.AclEntry;
import net.sf.acegisecurity.acl.AclManager;
import net.sf.acegisecurity.acl.basic.AbstractBasicAclEntry;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.util.ExpressionEvaluationUtils;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.servlet.ServletContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;
import javax.servlet.jsp.tagext.TagSupport;


/**
 * An implementation of {@link javax.servlet.jsp.tagext.Tag} that allows its
 * body through if some authorizations are granted to the request's principal.
 * 
 * <P>
 * Only works with permissions that are subclasses of {@link
 * net.sf.acegisecurity.acl.basic.AbstractBasicAclEntry}.
 * </p>
 * 
 * <p>
 * One or more comma separate integer permissions are specified via the
 * <code>hasPermission</code> attribute. The tag will include its body if
 * <b>any</b> of the integer permissions have been granted to the current
 * <code>Authentication</code> (obtained from the <code>ContextHolder</code>).
 * </p>
 * 
 * <p>
 * For this class to operate it must be able to access the application context
 * via the <code>WebApplicationContextUtils</code> and locate an {@link
 * AclManager}. Application contexts have no need to have more than one
 * <code>AclManager</code> (as a provider-based implementation can be used so
 * that it locates a provider that is authoritative for the given domain
 * object instance), so the first <code>AclManager</code> located will be
 * used.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclTag extends TagSupport {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(AclTag.class);

    //~ Instance fields ========================================================

    private Object domainObject;
    private String hasPermission = "";

    //~ Methods ================================================================

    public void setDomainObject(Object domainObject) {
        this.domainObject = domainObject;
    }

    public Object getDomainObject() {
        return domainObject;
    }

    public void setHasPermission(String hasPermission) {
        this.hasPermission = hasPermission;
    }

    public String getHasPermission() {
        return hasPermission;
    }

    public int doStartTag() throws JspException {
        if ((null == hasPermission) || "".equals(hasPermission)) {
            return Tag.SKIP_BODY;
        }

        final String evaledPermissionsString = ExpressionEvaluationUtils
            .evaluateString("hasPermission", hasPermission, pageContext);

        Integer[] requiredIntegers = null;

        try {
            requiredIntegers = parseIntegersString(evaledPermissionsString);
        } catch (NumberFormatException nfe) {
            throw new JspException(nfe);
        }

        Object resolvedDomainObject = null;

        if (domainObject instanceof String) {
            resolvedDomainObject = ExpressionEvaluationUtils.evaluate("domainObject",
                    (String) domainObject, Object.class, pageContext);
        } else {
            resolvedDomainObject = domainObject;
        }

        if (resolvedDomainObject == null) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "domainObject resolved to null, so including tag body");
            }

            // Of course they have access to a null object!
            return Tag.EVAL_BODY_INCLUDE;
        }

        if ((ContextHolder.getContext() == null)
            || !(ContextHolder.getContext() instanceof SecureContext)
            || (((SecureContext) ContextHolder.getContext()).getAuthentication() == null)) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "ContextHolder did not return a non-null Authentication object, so skipping tag body");
            }

            return Tag.SKIP_BODY;
        }

        Authentication auth = ((SecureContext) ContextHolder.getContext())
            .getAuthentication();

        ApplicationContext context = getContext(pageContext);
        Map beans = context.getBeansOfType(AclManager.class, false, false);

        if (beans.size() == 0) {
            throw new JspException(
                "No AclManager would found the application context: "
                + context.toString());
        }

        String beanName = (String) beans.keySet().iterator().next();
        AclManager aclManager = (AclManager) context.getBean(beanName);

        // Obtain aclEntrys applying to the current Authentication object
        AclEntry[] acls = aclManager.getAcls(resolvedDomainObject, auth);

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication: '" + auth + "' has: "
                + ((acls == null) ? 0 : acls.length)
                + " AclEntrys for domain object: '" + resolvedDomainObject
                + "' from AclManager: '" + aclManager.toString() + "'");
        }

        if ((acls == null) || (acls.length == 0)) {
            return Tag.SKIP_BODY;
        }

        for (int i = 0; i < acls.length; i++) {
            // Locate processable AclEntrys
            if (acls[i] instanceof AbstractBasicAclEntry) {
                AbstractBasicAclEntry processableAcl = (AbstractBasicAclEntry) acls[i];

                // See if principal has any of the required permissions
                for (int y = 0; y < requiredIntegers.length; y++) {
                    if (processableAcl.isPermitted(
                            requiredIntegers[y].intValue())) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "Including tag body as found permission: "
                                + requiredIntegers[y] + " due to AclEntry: '"
                                + processableAcl + "'");
                        }

                        return Tag.EVAL_BODY_INCLUDE;
                    }
                }
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No permission, so skipping tag body");
        }

        return Tag.SKIP_BODY;
    }

    /**
     * Allows test cases to override where application context obtained from.
     *
     * @param pageContext so the <code>ServletContext</code> can be accessed as
     *        required by Spring's <code>WebApplicationContextUtils</code>
     *
     * @return the Spring application context (never <code>null</code>)
     */
    protected ApplicationContext getContext(PageContext pageContext) {
        ServletContext servletContext = pageContext.getServletContext();

        return WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
    }

    private Integer[] parseIntegersString(String integersString)
        throws NumberFormatException {
        final Set integers = new HashSet();
        final StringTokenizer tokenizer;
        tokenizer = new StringTokenizer(integersString, ",", false);

        while (tokenizer.hasMoreTokens()) {
            String integer = tokenizer.nextToken();
            integers.add(new Integer(integer));
        }

        return (Integer[]) integers.toArray(new Integer[] {});
    }
}
