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

    public void invokeContactManager(String username, int nrOfCalls) {
        StopWatch stopWatch = new StopWatch(nrOfCalls
                + " ContactManager call(s)");
        Map orderServices = this.beanFactory.getBeansOfType(ContactManager.class,
                true, true);

        for (Iterator it = orderServices.keySet().iterator(); it.hasNext();) {
            String beanName = (String) it.next();

            ContactManager remoteContactManager = (ContactManager) orderServices
                .get(beanName);
            System.out.println("Calling ContactManager '" + beanName
                + "' for owner " + username);
            stopWatch.start(beanName);

            Contact[] contacts = null;

            for (int i = 0; i < nrOfCalls; i++) {
                contacts = remoteContactManager.getAllByOwner(username);
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
                "You need to specify a user ID and optionally a number of calls, e.g. for user marissa: "
                + "'client marissa' for a single call per service or 'client marissa 10' for 10 calls each");
        } else {
            String username = args[0];
            int nrOfCalls = 1;

            if ((args.length > 1) && !"".equals(args[1])) {
                nrOfCalls = Integer.parseInt(args[1]);
            }

            ListableBeanFactory beanFactory = new FileSystemXmlApplicationContext(
                    "clientContext.xml");
            ClientApplication client = new ClientApplication(beanFactory);
            client.invokeContactManager(username, nrOfCalls);
        }
    }
}
