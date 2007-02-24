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
package org.acegisecurity.taglibs.authz;

import org.acegisecurity.acls.Acl;
import org.acegisecurity.acls.AclService;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.domain.BasePermission;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityRetrievalStrategy;
import org.acegisecurity.acls.objectidentity.ObjectIdentityRetrievalStrategyImpl;
import org.acegisecurity.acls.sid.Sid;
import org.acegisecurity.acls.sid.SidRetrievalStrategy;
import org.acegisecurity.acls.sid.SidRetrievalStrategyImpl;

import org.acegisecurity.context.SecurityContextHolder;

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
 * An implementation of {@link javax.servlet.jsp.tagext.Tag} that allows its body through if some authorizations
 * are granted to the request's principal.<p>One or more comma separate numeric are specified via the
 * <code>hasPermission</code> attribute. Those permissions are then converted into {@link Permission} instances. These
 * instances are then presented as an array to the {@link Acl#isGranted(Permission[],
 * org.acegisecurity.acls.sid.Sid[], boolean)} method. The {@link Sid} presented is determined by the {@link
 * SidRetrievalStrategy}.</p>
 *  <p>For this class to operate it must be able to access the application context via the
 * <code>WebApplicationContextUtils</code> and locate an {@link AclService} and {@link SidRetrievalStrategy}.
 * Application contexts must provide one and only one of these Java types.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AccessControlListTag extends TagSupport {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(AccessControlListTag.class);

    //~ Instance fields ================================================================================================

    private AclService aclService;
    private ApplicationContext applicationContext;
    private Object domainObject;
    private ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy;
    private SidRetrievalStrategy sidRetrievalStrategy;
    private String hasPermission = "";

    //~ Methods ========================================================================================================

    public int doStartTag() throws JspException {
        initializeIfRequired();

        if ((null == hasPermission) || "".equals(hasPermission)) {
            return Tag.SKIP_BODY;
        }

        final String evaledPermissionsString = ExpressionEvaluationUtils.evaluateString("hasPermission", hasPermission,
                pageContext);

        Permission[] requiredPermissions = null;

        try {
            requiredPermissions = parsePermissionsString(evaledPermissionsString);
        } catch (NumberFormatException nfe) {
            throw new JspException(nfe);
        }

        Object resolvedDomainObject = null;

        if (domainObject instanceof String) {
            resolvedDomainObject = ExpressionEvaluationUtils.evaluate("domainObject", (String) domainObject,
                    Object.class, pageContext);
        } else {
            resolvedDomainObject = domainObject;
        }

        if (resolvedDomainObject == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("domainObject resolved to null, so including tag body");
            }

            // Of course they have access to a null object!
            return Tag.EVAL_BODY_INCLUDE;
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "SecurityContextHolder did not return a non-null Authentication object, so skipping tag body");
            }

            return Tag.SKIP_BODY;
        }

        Sid[] sids = sidRetrievalStrategy.getSids(SecurityContextHolder.getContext().getAuthentication());
        ObjectIdentity oid = objectIdentityRetrievalStrategy.getObjectIdentity(resolvedDomainObject);

        // Obtain aclEntrys applying to the current Authentication object
        try {
            Acl acl = aclService.readAclById(oid, sids);

            if (acl.isGranted(requiredPermissions, sids, false)) {
                return Tag.EVAL_BODY_INCLUDE;
            } else {
                return Tag.SKIP_BODY;
            }
        } catch (NotFoundException nfe) {
            return Tag.SKIP_BODY;
        }
    }

    /**
     * Allows test cases to override where application context obtained from.
     *
     * @param pageContext so the <code>ServletContext</code> can be accessed as required by Spring's
     *        <code>WebApplicationContextUtils</code>
     *
     * @return the Spring application context (never <code>null</code>)
     */
    protected ApplicationContext getContext(PageContext pageContext) {
        ServletContext servletContext = pageContext.getServletContext();

        return WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
    }

    public Object getDomainObject() {
        return domainObject;
    }

    public String getHasPermission() {
        return hasPermission;
    }

    private void initializeIfRequired() throws JspException {
        if (applicationContext == null) {
            this.applicationContext = getContext(pageContext);

            Map map = applicationContext.getBeansOfType(AclService.class);

            if (map.size() != 1) {
                throw new JspException(
                    "Found incorrect number of AclService instances in application context - you must have only have one!");
            }

            aclService = (AclService) map.values().iterator().next();

            map = applicationContext.getBeansOfType(SidRetrievalStrategy.class);

            if (map.size() == 0) {
                sidRetrievalStrategy = new SidRetrievalStrategyImpl();
            } else if (map.size() == 1) {
                sidRetrievalStrategy = (SidRetrievalStrategy) map.values().iterator().next();
            } else {
                throw new JspException("Found incorrect number of SidRetrievalStrategy instances in application "
                        + "context - you must have only have one!");
            }

            map = applicationContext.getBeansOfType(ObjectIdentityRetrievalStrategy.class);

            if (map.size() == 0) {
                objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();
            } else if (map.size() == 1) {
                objectIdentityRetrievalStrategy = (ObjectIdentityRetrievalStrategy) map.values().iterator().next();
            } else {
                throw new JspException("Found incorrect number of ObjectIdentityRetrievalStrategy instances in "
                        + "application context - you must have only have one!");
            }
        }
    }

    private Permission[] parsePermissionsString(String integersString)
        throws NumberFormatException {
        final Set permissions = new HashSet();
        final StringTokenizer tokenizer;
        tokenizer = new StringTokenizer(integersString, ",", false);

        while (tokenizer.hasMoreTokens()) {
            String integer = tokenizer.nextToken();
            permissions.add(BasePermission.buildFromMask(new Integer(integer).intValue()));
        }

        return (Permission[]) permissions.toArray(new Permission[] {});
    }

    public void setDomainObject(Object domainObject) {
        this.domainObject = domainObject;
    }

    public void setHasPermission(String hasPermission) {
        this.hasPermission = hasPermission;
    }
}
