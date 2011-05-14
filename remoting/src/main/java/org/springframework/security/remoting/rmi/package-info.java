/**
 * Enables use of Spring's RMI remoting extension points to propagate the <code>SecurityContextHolder</code> (which
 * should contain an <code>Authentication</code> request token) from one JVM to the remote JVM.
 * <p>
 * The beans are wired as follows:
 * <pre>
 * &lt;bean id="test" class="org.springframework.remoting.rmi.RmiProxyFactoryBean"&gt;
 *   &lt;property name="serviceUrl"&gt;&lt;value&gt;rmi://localhost/Test&lt;/value&gt;&lt;/property&gt;
 *   &lt;property name="serviceInterface"&gt;&lt;value&gt;test.TargetInterface&lt;/value&gt;&lt;/property&gt;
 *   &lt;property name="refreshStubOnConnectFailure"&gt;&lt;value&gt;true&lt;/value&gt;&lt;/property&gt;
 *   &lt;property name="remoteInvocationFactory"&gt;&lt;ref bean="remoteInvocationFactory"/&gt;&lt;/property&gt;
 * &lt;/bean&gt;
 *
 * &lt;bean id="remoteInvocationFactory"
 *     class="org.springframework.security.remoting.rmi.ContextPropagatingRemoteInvocationFactory"/&gt;
 * </pre>
 */
package org.springframework.security.remoting.rmi;
