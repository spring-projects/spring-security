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
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import java.io.IOException;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;
import javax.servlet.jsp.tagext.TagSupport;


/**
 * An {@link javax.servlet.jsp.tagext.Tag} implementation that allows
 * convenient access to the current <code>Authentication</code> object.
 * 
 * <p>
 * Whilst JSPs can access the <code>ContextHolder</code> directly, this tag
 * avoids handling <code>null</code> and the incorrect type of
 * <code>Context</code> in the <code>ContextHolder</code>. The tag also
 * properly accommodates <code>Authentication.getPrincipal()</code>, which can
 * either be a <code>String</code> or a <code>UserDetails</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationTag extends TagSupport {
    //~ Static fields/initializers =============================================

    public static final String OPERATION_PRINCIPAL = "principal";

    //~ Instance fields ========================================================

    private String operation = "";

    //~ Methods ================================================================

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getOperation() {
        return operation;
    }

    public int doStartTag() throws JspException {
        if ((null == operation) || "".equals(operation)) {
            return Tag.SKIP_BODY;
        }

        if (!OPERATION_PRINCIPAL.equalsIgnoreCase(operation)) {
            throw new JspException("Unsupported use of auth:authentication tag");
        }

        if ((ContextHolder.getContext() == null)
            || !(ContextHolder.getContext() instanceof SecureContext)
            || (((SecureContext) ContextHolder.getContext()).getAuthentication() == null)) {
            return Tag.SKIP_BODY;
        }

        Authentication auth = ((SecureContext) ContextHolder.getContext())
            .getAuthentication();

        if (auth.getPrincipal() == null) {
            return Tag.SKIP_BODY;
        } else if (auth.getPrincipal() instanceof UserDetails) {
            writeMessage(((UserDetails) auth.getPrincipal()).getUsername());

            return Tag.SKIP_BODY;
        } else {
            writeMessage(auth.getPrincipal().toString());

            return Tag.SKIP_BODY;
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
