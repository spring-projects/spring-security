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

import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Constructor;


/**
 * Associates a given {@link SecurityContext} with the current execution
 * thread.
 * 
 * <p>
 * This class provides a series of static methods that delegate to an instance
 * of {@link org.acegisecurity.context.SecurityContextHolderStrategy}. The
 * purpose of the class is to provide a convenient way to specify the strategy
 * that should be used for a given JVM. This is a JVM-wide setting, since
 * everything in this class is <code>static</code> to facilitate ease of use
 * in calling code.
 * </p>
 * 
 * <p>
 * To specify which strategy should be used, you must provide a mode setting. A
 * mode setting is one of the three valid <code>MODE_</code> settings defined
 * as <code>static final</code> fields, or a fully qualified classname to a
 * concrete implementation of {@link
 * org.acegisecurity.context.SecurityContextHolderStrategy} that provides a
 * public no-argument constructor.
 * </p>
 * 
 * <p>
 * There are two ways to specify the desired mode <code>String</code>. The
 * first is to specify it via the system property keyed on {@link
 * #SYSTEM_PROPERTY}. The second is to call {@link #setStrategyName(String)}
 * before using the class. If neither approach is used, the class will default
 * to using {@link #MODE_THREADLOCAL}, which is backwards compatible, has
 * fewer JVM incompatibilities and is appropriate on servers (whereas {@link
 * #MODE_GLOBAL} is not).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see org.acegisecurity.context.HttpSessionContextIntegrationFilter
 */
public class SecurityContextHolder {
    //~ Static fields/initializers =============================================

    public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";
    public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";
    public static final String MODE_GLOBAL = "MODE_GLOBAL";
    public static final String SYSTEM_PROPERTY = "acegi.security.strategy";
    private static String strategyName = System.getProperty(SYSTEM_PROPERTY);
    private static Constructor customStrategy;
    private static SecurityContextHolderStrategy strategy;

    //~ Methods ================================================================

    /**
     * Explicitly clears the context value from the current thread.
     */
    public static void clearContext() {
        initialize();
        strategy.clearContext();
    }

    /**
     * Obtain the current <code>SecurityContext</code>.
     *
     * @return the security context (never <code>null</code>)
     */
    public static SecurityContext getContext() {
        initialize();

        return strategy.getContext();
    }

    private static void initialize() {
        if ((strategyName == null) || "".equals(strategyName)) {
            // Set default
            strategyName = MODE_THREADLOCAL;
        }

        if (strategyName.equals(MODE_THREADLOCAL)) {
            strategy = new ThreadLocalSecurityContextHolderStrategy();
        } else if (strategyName.equals(MODE_INHERITABLETHREADLOCAL)) {
            strategy = new InheritableThreadLocalSecurityContextHolderStrategy();
        } else if (strategyName.equals(MODE_GLOBAL)) {
            strategy = new GlobalSecurityContextHolderStrategy();
        } else {
            // Try to load a custom strategy
            try {
                if (customStrategy == null) {
                    Class clazz = Class.forName(strategyName);
                    customStrategy = clazz.getConstructor(new Class[] {});
                }

                strategy = (SecurityContextHolderStrategy) customStrategy
                    .newInstance(new Object[] {});
            } catch (Exception ex) {
                ReflectionUtils.handleReflectionException(ex);
            }
        }
    }

    /**
     * Associates a new <code>SecurityContext</code> with the current thread of
     * execution.
     *
     * @param context the new <code>SecurityContext</code> (may not be
     *        <code>null</code>)
     */
    public static void setContext(SecurityContext context) {
        initialize();
        strategy.setContext(context);
    }

    /**
     * Changes the preferred strategy. Do <em>NOT</em> call this method more
     * than once for a given JVM, as it will reinitialize the strategy and
     * adversely affect any existing threads using the old strategy.
     *
     * @param strategyName the fully qualified classname of the strategy that
     *        should be used.
     */
    public static void setStrategyName(String strategyName) {
        SecurityContextHolder.strategyName = strategyName;
        initialize();
    }

    public String toString() {
        return "SecurityContextHolder[strategy='" + strategyName + "']";
    }
}
