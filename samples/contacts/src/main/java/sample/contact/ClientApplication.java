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

package sample.contact;

import org.springframework.beans.factory.ListableBeanFactory;

import org.springframework.context.support.FileSystemXmlApplicationContext;

import org.springframework.util.StopWatch;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import java.util.Iterator;
import java.util.Map;


/**
 * Demonstrates accessing the {@link ContactManager} via remoting protocols.
 * 
 * <P>
 * Based on Spring's JPetStore sample, written by Juergen Hoeller.
 * </p>
 *
 * @author Ben Alex
 */
public class ClientApplication {
    //~ Instance fields ========================================================

    private final ListableBeanFactory beanFactory;

    //~ Constructors ===========================================================

    public ClientApplication(ListableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    //~ Methods ================================================================

    public void invokeContactManager(String forOwner, String username,
        String password, int nrOfCalls) {
        StopWatch stopWatch = new StopWatch(nrOfCalls
                + " ContactManager call(s)");
        Map orderServices = this.beanFactory.getBeansOfType(ContactManager.class,
                true, true);

        for (Iterator it = orderServices.keySet().iterator(); it.hasNext();) {
            String beanName = (String) it.next();

            ContactManager remoteContactManager = (ContactManager) orderServices
                .get(beanName);
            System.out.println("Calling ContactManager '" + beanName
                + "' for owner " + forOwner);

            Object object = this.beanFactory.getBean("&" + beanName);

            try {
                System.out.println("Trying to find setUsername(String) method");

                Method method = object.getClass().getMethod("setUsername",
                        new Class[] {String.class});
                System.out.println("Found; Trying to setUsername(String) to "
                    + username);
                method.invoke(object, new Object[] {username});
            } catch (NoSuchMethodException ignored) {
                ignored.printStackTrace();
            } catch (IllegalAccessException ignored) {
                ignored.printStackTrace();
            } catch (InvocationTargetException ignored) {
                ignored.printStackTrace();
            }

            try {
                System.out.println("Trying to find setPassword(String) method");

                Method method = object.getClass().getMethod("setPassword",
                        new Class[] {String.class});
                method.invoke(object, new Object[] {password});
                System.out.println("Found; Trying to setPassword(String) to "
                    + password);
            } catch (NoSuchMethodException ignored) {}
             catch (IllegalAccessException ignored) {}
             catch (InvocationTargetException ignored) {}

            stopWatch.start(beanName);

            Contact[] contacts = null;

            for (int i = 0; i < nrOfCalls; i++) {
                contacts = remoteContactManager.getAllByOwner(forOwner);
            }

            stopWatch.stop();

            if (contacts.length != 0) {
                for (int i = 0; i < contacts.length; i++) {
                    System.out.println("Contact " + i + ": "
                        + contacts[i].toString());
                }
            } else {
                System.out.println("No contacts found belonging to owner");
            }

            System.out.println();
        }

        System.out.println(stopWatch.prettyPrint());
    }

    public static void main(String[] args) {
        if ((args.length == 0) || "".equals(args[0])) {
            System.out.println(
                "You need to specify the owner to request contacts for, the user ID to use, the password to use, and optionally a number of calls, e.g. for user marissa: "
                + "'client marissa marissa koala' for a single call per service or 'client marissa marissa koala 10' for 10 calls each");
        } else {
            String forOwner = args[0];
            String username = args[1];
            String password = args[2];

            int nrOfCalls = 1;

            if ((args.length > 3) && !"".equals(args[3])) {
                nrOfCalls = Integer.parseInt(args[3]);
            }

            ListableBeanFactory beanFactory = new FileSystemXmlApplicationContext(
                    "clientContext.xml");
            ClientApplication client = new ClientApplication(beanFactory);
            client.invokeContactManager(forOwner, username, password, nrOfCalls);
        }
    }
}
