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

package org.acegisecurity.providers.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import javax.naming.Context;
import javax.naming.NamingException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * LDAP Utility methods.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUtils {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(LdapUtils.class);

    //~ Methods ================================================================

    public static void closeContext(Context ctx) {
        try {
            if (ctx != null) {
                ctx.close();
            }
        } catch (NamingException e) {
            logger.error("Failed to close context.", e);
        }
    }

    /**
     * Parses the supplied LDAP URL.
     * @param url the URL (e.g. <tt>ldap://monkeymachine:11389/dc=acegisecurity,dc=org</tt>).
     * @return the URI object created from the URL
     * @throws IllegalArgumentException if the URL is null, empty or the URI syntax is invalid.
     */
    public static URI parseLdapUrl(String url) {
        Assert.hasLength(url);

        try {
            return new URI(url);
        } catch (URISyntaxException e) {
            logger.error("Failed to parse url " + url, e);
            throw new IllegalArgumentException("Unable to parse url: " + url);
        }
    }

    public static byte[] getUtf8Bytes(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // Should be impossible since UTF-8 is required by all implementations
            throw new IllegalStateException("Failed to convert string to UTF-8 bytes. Shouldn't be possible");
        }
    }

    public static String escapeNameForFilter(String name) {
        // TODO: Implement escaping as defined in RFC 2254
        // Think this is probably not needed as filter args should be escaped automatically
        // by the search methods.

        return name;
    }

    /**
     * Obtains the part of a DN relative to a supplied base context.
     * <p>
     * If the DN is "cn=bob,ou=people,dc=acegisecurity,dc=org" and the base context
     * name is "ou=people,dc=acegisecurity,dc=org" it would return "cn=bob".
     * </p>
     *
     * @param fullDn the DN
     * @param baseCtx the context to work out the name relative to.
     * @return the
     * @throws NamingException any exceptions thrown by the context are propagated.
     */
    public static String getRelativeName(String fullDn, Context baseCtx) throws NamingException {
        String baseDn = baseCtx.getNameInNamespace();

        if (baseDn.length() == 0) {
            return fullDn;
        }

        if (baseDn.equals(fullDn)) {
            return "";
        }

        int index = fullDn.lastIndexOf(baseDn);

        Assert.isTrue(index > 0, "Context base DN is not contained in the full DN");

        // remove the base name and preceding comma.
        return fullDn.substring(0, index - 1);
    }
}
