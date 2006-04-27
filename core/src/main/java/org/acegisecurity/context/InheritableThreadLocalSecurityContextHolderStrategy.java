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

package org.acegisecurity.context;

import org.springframework.util.Assert;


/**
 * An <code>InheritableThreadLocal</code>-based implementation of {@link
 * org.acegisecurity.context.SecurityContextHolderStrategy}.
 *
 * @author Ben Alex
 * @version $Id: SecurityContextHolder.java 1324 2006-02-12 06:29:53Z benalex $
 *
 * @see java.lang.ThreadLocal
 * @see org.acegisecurity.context.HttpSessionContextIntegrationFilter
 */
public class InheritableThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {
    //~ Static fields/initializers =============================================

    private static ThreadLocal contextHolder = new InheritableThreadLocal();

    //~ Methods ================================================================

    public void clearContext() {
        contextHolder.set(null);
    }

    public SecurityContext getContext() {
        if (contextHolder.get() == null) {
            contextHolder.set(new SecurityContextImpl());
        }

        return (SecurityContext) contextHolder.get();
    }

    public void setContext(SecurityContext context) {
        Assert.notNull(context,
            "Only non-null SecurityContext instances are permitted");
        contextHolder.set(context);
    }
}
