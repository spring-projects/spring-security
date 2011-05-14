/**
 * Enables use of Spring's <code>HttpInvoker</code> extension points to
 * present the <code>principal</code> and <code>credentials</code> located
 * in the <code>ContextHolder</code> via BASIC authentication.
 * <p>
 * The beans are wired as follows:
 *
 * <pre>
 * &lt;bean id="test" class="org.springframework.remoting.httpinvoker.HttpInvokerProxyFactoryBean"&gt;
 *   &lt;property name="serviceUrl"&gt;&lt;value&gt;http://localhost/Test&lt;/value&gt;&lt;/property&gt;
 *   &lt;property name="serviceInterface"&gt;&lt;value&gt;test.TargetInterface&lt;/value&gt;&lt;/property&gt;
 *   &lt;property name="httpInvokerRequestExecutor"&gt;&lt;ref bean="httpInvokerRequestExecutor"/&gt;&lt;/property&gt;
 * &lt;/bean&gt;
 *
 * &lt;bean id="httpInvokerRequestExecutor"
 *     class="org.springframework.security.core.context.httpinvoker.AuthenticationSimpleHttpInvokerRequestExecutor"/&gt;
 * </pre>
 */
package org.springframework.security.remoting.httpinvoker;
