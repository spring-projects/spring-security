/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.taglibs.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.taglibs.TagLibConfig;
import org.springframework.security.web.context.support.SecurityWebApplicationContextUtils;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;
import javax.servlet.jsp.tagext.TagSupport;
import java.util.*;


/**
 * An implementation of {@link Tag} that allows its body through if some authorizations are granted to the request's
 * principal.
 * <p>
 * One or more comma separate numeric are specified via the {@code hasPermission} attribute. The tag delegates
 * to the configured {@link PermissionEvaluator} which it obtains from the {@code ApplicationContext}.
 * <p>
 * For this class to operate it must be able to access the application context via the
 * {@code WebApplicationContextUtils} and attempt to locate the {@code PermissionEvaluator} instance.
 * There cannot be more than one of these present for the tag to function.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
public class AccessControlListTag extends TagSupport {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(AccessControlListTag.class);

    //~ Instance fields ================================================================================================

    private ApplicationContext applicationContext;
    private Object domainObject;
    private PermissionEvaluator permissionEvaluator;
    private String hasPermission = "";
    private String var;

    //~ Methods ========================================================================================================

    public int doStartTag() throws JspException {
        if ((null == hasPermission) || "".equals(hasPermission)) {
            return skipBody();
        }

        initializeIfRequired();

        if (domainObject == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("domainObject resolved to null, so including tag body");
            }

            // Of course they have access to a null object!
            return evalBody();
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "SecurityContextHolder did not return a non-null Authentication object, so skipping tag body");
            }

            return skipBody();
        }

        List<Object> requiredPermissions = parseHasPermission(hasPermission);
        for(Object requiredPermission : requiredPermissions) {
            if (!permissionEvaluator.hasPermission(authentication, domainObject, requiredPermission)) {
                return skipBody();
            }
        }

        return evalBody();
    }

    private List<Object> parseHasPermission(String hasPermission) {
        String[] requiredPermissions = hasPermission.split(",");
        List<Object> parsedPermissions = new ArrayList<Object>(requiredPermissions.length);
        for(String permissionToParse : requiredPermissions) {
            Object parsedPermission = permissionToParse;
            try {
                parsedPermission = Integer.parseInt(permissionToParse);
            }catch(NumberFormatException notBitMask) {}
            parsedPermissions.add(parsedPermission);
        }
        return parsedPermissions;
    }

    private int skipBody() {
        if (var != null) {
            pageContext.setAttribute(var, Boolean.FALSE, PageContext.PAGE_SCOPE);
        }
        return TagLibConfig.evalOrSkip(false);
    }

    private int evalBody() {
        if (var != null) {
            pageContext.setAttribute(var, Boolean.TRUE, PageContext.PAGE_SCOPE);
        }
        return TagLibConfig.evalOrSkip(true);
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

        return SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(servletContext);
    }

    public Object getDomainObject() {
        return domainObject;
    }

    public String getHasPermission() {
        return hasPermission;
    }

    private void initializeIfRequired() throws JspException {
        if (applicationContext != null) {
            return;
        }

        this.applicationContext = getContext(pageContext);

        permissionEvaluator = getBeanOfType(PermissionEvaluator.class);
    }

    private <T> T getBeanOfType(Class<T> type) throws JspException {
        Map<String, T> map = applicationContext.getBeansOfType(type);

        for (ApplicationContext context = applicationContext.getParent();
            context != null; context = context.getParent()) {
            map.putAll(context.getBeansOfType(type));
        }

        if (map.size() == 0) {
            return null;
        } else if (map.size() == 1) {
            return map.values().iterator().next();
        }

        throw new JspException("Found incorrect number of " + type.getSimpleName() +" instances in "
                    + "application context - you must have only have one!");
    }

    public void setDomainObject(Object domainObject) {
        this.domainObject = domainObject;
    }

    public void setHasPermission(String hasPermission) {
        this.hasPermission = hasPermission;
    }

    public void setVar(String var) {
        this.var = var;
    }
}
