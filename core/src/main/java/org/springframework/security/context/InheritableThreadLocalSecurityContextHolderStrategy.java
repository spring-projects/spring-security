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

package org.springframework.security.context;

import org.springframework.util.Assert;


/**
 * An <code>InheritableThreadLocal</code>-based implementation of {@link
 * org.springframework.security.context.SecurityContextHolderStrategy}.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see java.lang.ThreadLocal
 * @see org.springframework.security.context.web.SecurityContextPersistenceFilter
 */
public class InheritableThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {
    //~ Static fields/initializers =====================================================================================

    private static ThreadLocal<SecurityContext> contextHolder = new InheritableThreadLocal<SecurityContext>();

    //~ Methods ========================================================================================================

    public void clearContext() {
        contextHolder.set(null);
    }

    public SecurityContext getContext() {
        if (contextHolder.get() == null) {
            contextHolder.set(new SecurityContextImpl());
        }

        return contextHolder.get();
    }

    public void setContext(SecurityContext context) {
        Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
        contextHolder.set(context);
    }

    public SecurityContext createEmptyContext() {
        return new SecurityContextImpl();
    }
}
