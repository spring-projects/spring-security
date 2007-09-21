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

package org.springframework.security.taglibs.authz;

import org.springframework.security.Authentication;

import org.springframework.security.context.SecurityContext;
import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.userdetails.UserDetails;

import java.io.IOException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;
import javax.servlet.jsp.tagext.TagSupport;


/**
 * An {@link javax.servlet.jsp.tagext.Tag} implementation that allows convenient access to the current
 * <code>Authentication</code> object.<p>Whilst JSPs can access the <code>SecurityContext</code> directly, this tag
 * avoids handling <code>null</code> conditions. The tag also properly accommodates
 * <code>Authentication.getPrincipal()</code>, which can either be a <code>String</code> or a
 * <code>UserDetails</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationTag extends TagSupport {
    //~ Static fields/initializers =====================================================================================

    private static final Set methodPrefixValidOptions = new HashSet();

    static {
        methodPrefixValidOptions.add("get");
        methodPrefixValidOptions.add("is");
    }

    //~ Instance fields ================================================================================================

    private String methodPrefix = "get";
    private String operation = "";

    //~ Methods ========================================================================================================

    public int doStartTag() throws JspException {
        if ((null == operation) || "".equals(operation)) {
            return Tag.SKIP_BODY;
        }

        validateArguments();

        if ((SecurityContextHolder.getContext() == null)
            || !(SecurityContextHolder.getContext() instanceof SecurityContext)
            || (((SecurityContext) SecurityContextHolder.getContext()).getAuthentication() == null)) {
            return Tag.SKIP_BODY;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth.getPrincipal() == null) {
            return Tag.SKIP_BODY;
        } else if (auth.getPrincipal() instanceof UserDetails) {
            writeMessage(invokeOperation(auth.getPrincipal()));

            return Tag.SKIP_BODY;
        } else {
            writeMessage(auth.getPrincipal().toString());

            return Tag.SKIP_BODY;
        }
    }

    public String getMethodPrefix() {
        return methodPrefix;
    }

    public String getOperation() {
        return operation;
    }

    protected String invokeOperation(Object obj) throws JspException {
        Class clazz = obj.getClass();
        String methodToInvoke = getOperation();
        StringBuffer methodName = new StringBuffer();
        methodName.append(getMethodPrefix());
        methodName.append(methodToInvoke.substring(0, 1).toUpperCase());
        methodName.append(methodToInvoke.substring(1));

        Method method = null;

        try {
            method = clazz.getMethod(methodName.toString(), (Class[]) null);
        } catch (SecurityException se) {
            throw new JspException(se);
        } catch (NoSuchMethodException nsme) {
            throw new JspException(nsme);
        }

        Object retVal = null;

        try {
            retVal = method.invoke(obj, (Object[]) null);
        } catch (IllegalArgumentException iae) {
            throw new JspException(iae);
        } catch (IllegalAccessException iae) {
            throw new JspException(iae);
        } catch (InvocationTargetException ite) {
            throw new JspException(ite);
        }

        if (retVal == null) {
            retVal = "";
        }

        return retVal.toString();
    }

    public void setMethodPrefix(String methodPrefix) {
        this.methodPrefix = methodPrefix;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    protected void validateArguments() throws JspException {
        if ((getMethodPrefix() != null) && !getMethodPrefix().equals("")) {
            if (!methodPrefixValidOptions.contains(getMethodPrefix())) {
                throw new JspException("Authorization tag : no valid method prefix available");
            }
        } else {
            throw new JspException("Authorization tag : no method prefix available");
        }
    }

    protected void writeMessage(String msg) throws JspException {
        try {
            pageContext.getOut().write(String.valueOf(msg));
        } catch (IOException ioe) {
            throw new JspException(ioe);
        }
    }
}
