/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package sample.contact;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.support.FileSystemXmlApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StopWatch;

/**
 * Demonstrates accessing the {@link ContactManager} via remoting protocols.
 * <p>
 * Based on Spring's JPetStore sample, written by Juergen Hoeller.
 *
 * @author Ben Alex
 */
public class ClientApplication {
	// ~ Instance fields
	// ================================================================================================

	private final ListableBeanFactory beanFactory;

	// ~ Constructors
	// ===================================================================================================

	public ClientApplication(ListableBeanFactory beanFactory) {
		this.beanFactory = beanFactory;
	}

	// ~ Methods
	// ========================================================================================================

	public void invokeContactManager(Authentication authentication, int nrOfCalls) {
		StopWatch stopWatch = new StopWatch(nrOfCalls + " ContactManager call(s)");
		Map<String, ContactManager> contactServices = this.beanFactory.getBeansOfType(
				ContactManager.class, true, true);

		SecurityContextHolder.getContext().setAuthentication(authentication);

		for (Map.Entry<String, ContactManager> entry : contactServices.entrySet()) {
			String beanName = entry.getKey();
			ContactManager remoteContactManager = entry.getValue();
			Object object = this.beanFactory.getBean("&" + beanName);

			try {
				System.out.println("Trying to find setUsername(String) method on: "
						+ object.getClass().getName());

				Method method = object.getClass().getMethod("setUsername",
						new Class[] { String.class });
				System.out.println("Found; Trying to setUsername(String) to "
						+ authentication.getPrincipal());
				method.invoke(object, authentication.getPrincipal());
			}
			catch (NoSuchMethodException ignored) {
				System.out
						.println("This client proxy factory does not have a setUsername(String) method");
			}
			catch (IllegalAccessException | InvocationTargetException ignored) {
				ignored.printStackTrace();
			}

			try {
				System.out.println("Trying to find setPassword(String) method on: "
						+ object.getClass().getName());

				Method method = object.getClass().getMethod("setPassword",
						new Class[] { String.class });
				method.invoke(object, authentication.getCredentials());
				System.out.println("Found; Trying to setPassword(String) to "
						+ authentication.getCredentials());
			}
			catch (NoSuchMethodException ignored) {
				System.out
						.println("This client proxy factory does not have a setPassword(String) method");
			}
			catch (IllegalAccessException | InvocationTargetException ignored) {
			}

			System.out.println("Calling ContactManager '" + beanName + "'");

			stopWatch.start(beanName);

			List<Contact> contacts = null;

			for (int i = 0; i < nrOfCalls; i++) {
				contacts = remoteContactManager.getAll();
			}

			stopWatch.stop();

			if (contacts.size() != 0) {
				for (Contact contact : contacts) {
					System.out.println("Contact: " + contact);
				}
			}
			else {
				System.out.println("No contacts found which this user has permission to");
			}

			System.out.println();
			System.out.println(stopWatch.prettyPrint());
		}

		SecurityContextHolder.clearContext();
	}

	public static void main(String[] args) {
		String username = System.getProperty("username", "");
		String password = System.getProperty("password", "");
		String nrOfCallsString = System.getProperty("nrOfCalls", "");

		if ("".equals(username) || "".equals(password)) {
			System.out
					.println("You need to specify the user ID to use, the password to use, and optionally a number of calls "
							+ "using the username, password, and nrOfCalls system properties respectively. eg for user rod, "
							+ "use: -Dusername=rod -Dpassword=koala' for a single call per service and "
							+ "use: -Dusername=rod -Dpassword=koala -DnrOfCalls=10 for ten calls per service.");
			System.exit(-1);
		}
		else {
			int nrOfCalls = 1;

			if (!"".equals(nrOfCallsString)) {
				nrOfCalls = Integer.parseInt(nrOfCallsString);
			}

			ListableBeanFactory beanFactory = new FileSystemXmlApplicationContext(
					"clientContext.xml");
			ClientApplication client = new ClientApplication(beanFactory);

			client.invokeContactManager(new UsernamePasswordAuthenticationToken(username,
					password), nrOfCalls);
			System.exit(0);
		}
	}
}
