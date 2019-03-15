/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

