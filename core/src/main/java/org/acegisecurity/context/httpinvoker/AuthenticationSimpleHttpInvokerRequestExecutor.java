/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context.httpinvoker;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationCredentialsNotFoundException;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.remoting.httpinvoker.SimpleHttpInvokerRequestExecutor;

import java.io.IOException;

import java.net.HttpURLConnection;


/**
 * Adds BASIC authentication support to
 * <code>SimpleHttpInvokerRequestExecutor</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationSimpleHttpInvokerRequestExecutor
    extends SimpleHttpInvokerRequestExecutor {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(AuthenticationSimpleHttpInvokerRequestExecutor.class);

    //~ Methods ================================================================

    /**
     * Provided so subclasses can perform additional configuration if required
     * (eg set additional request headers for non-security related information
     * etc).
     *
     * @param con the HTTP connection to prepare
     * @param contentLength the length of the content to send
     *
     * @throws IOException if thrown by HttpURLConnection methods
     */
    protected void doPrepareConnection(HttpURLConnection con, int contentLength)
        throws IOException {}

    /**
     * Called every time a HTTP invocation is made.
     * 
     * <P>
     * Simply allows the parent to setup the connection, and then adds an
     * <code>Authorization</code> HTTP header property that will be used for
     * BASIC authentication.
     * </p>
     * 
     * <P>
     * The <code>ContextHolder</code> is used to obtain the relevant principal
     * and credentials.
     * </p>
     *
     * @param con the HTTP connection to prepare
     * @param contentLength the length of the content to send
     *
     * @throws IOException if thrown by HttpURLConnection methods
     * @throws AuthenticationCredentialsNotFoundException if the
     *         <code>ContextHolder</code> does not contain a valid
     *         <code>Authentication</code> with both its
     *         <code>principal</code> and <code>credentials</code> not
     *         <code>null</code>
     */
    protected void prepareConnection(HttpURLConnection con, int contentLength)
        throws IOException, AuthenticationCredentialsNotFoundException {
        super.prepareConnection(con, contentLength);

        if ((ContextHolder.getContext() != null)
            && (ContextHolder.getContext() instanceof SecureContext)) {
            Authentication auth = ((SecureContext) ContextHolder.getContext())
                .getAuthentication();

            if ((auth != null) && (auth.getPrincipal() != null)
                && (auth.getCredentials() != null)) {
                String base64 = auth.getPrincipal().toString() + ":"
                    + auth.getCredentials().toString();
                con.setRequestProperty("Authorization",
                    "Basic "
                    + new String(Base64.encodeBase64(base64.getBytes())));

                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "HttpInvocation now presenting via BASIC authentication ContextHolder-derived: "
                        + auth.toString());
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "Unable to set BASIC authentication header as ContextHolder: "
                        + ContextHolder.getContext()
                        + "; did not provide valid Authentication: " + auth);
                }
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Unable to set BASIC authentication header as ContextHolder: "
                    + ContextHolder.getContext()
                    + "; does not provide a SecureContext");
            }
        }

        doPrepareConnection(con, contentLength);
    }
}
