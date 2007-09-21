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

package org.springframework.security.concurrent;

import junit.framework.TestCase;

import java.util.Set;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;

/**
 * Tests concurrency access to SessionRegistryImpl.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SessionRegistryImplMultithreadedTests extends TestCase {
    private static final Random rnd = new Random();
    private static boolean errorOccurred;

    protected void setUp() throws Exception {
        errorOccurred = false;
    }

    /**
     * Reproduces the NPE mentioned in SEC-484 where a sessionId is removed from
     * the set of sessions before it is removed from the list of sessions for a principal.
     * getAllSessions(principal, false) then finds the sessionId in the principal's session list
     * but reads null for the SessionInformation with the same Id.
     * Note that this is not guaranteed to produce the error but is a good testing point. Increasing the number
     * of sessions makes a failure more likely, but slows the test considerably.
     * Inserting temporary sleep statements in SessionRegistryClassImpl will also help.
     */
    public void testConcurrencyOfReadAndRemoveIsSafe() {
        Object principal = "Joe Principal";
        SessionRegistryImpl sessionregistry = new SessionRegistryImpl();
        Set sessions = Collections.synchronizedSet(new HashSet());
        // Register some sessions
        for (int i = 0; i < 50; i++) {
            String sessionId = Integer.toString(i);
            sessions.add(sessionId);
            sessionregistry.registerNewSession(sessionId, principal);
        }

        // Pile of readers to hammer the getAllSessions method.
        for (int i=0; i < 10; i++) {
            Thread reader = new Thread(new SessionRegistryReader(principal, sessionregistry));
            reader.start();
        }

        Thread remover = new Thread(new SessionRemover("remover", sessionregistry, sessions));

        remover.start();

        while(remover.isAlive()) {
            pause(250);
        }

        assertFalse("Thread errors detected; review log output for details", errorOccurred);
    }

    public void testConcurrentRemovalIsSafe() {
        Object principal = "Some principal object";
        SessionRegistryImpl sessionregistry = new SessionRegistryImpl();
        // The session list (effectivelly the containers sessions).
        Set sessions = Collections.synchronizedSet(new HashSet());
        Thread registerer = new Thread(new SessionRegisterer(principal, sessionregistry, 100, sessions));

        registerer.start();

        int nRemovers = 4;

        SessionRemover[] removers = new SessionRemover[nRemovers];
        Thread[] removerThreads = new Thread[nRemovers];

        for (int i = 0; i < removers.length; i++) {
            removers[i] = new SessionRemover("remover" + i, sessionregistry, sessions);
            removerThreads[i] = new Thread(removers[i], "remover" + i);
            removerThreads[i].start();
        }

        while (stillRunning(removerThreads)) {
            pause(500);
        }
    }

    private boolean stillRunning(Thread[] threads) {
        for (int i = 0; i < threads.length; i++) {
            if (threads[i].isAlive()) {
                return true;
            }
        }

        return false;
    }

    private static class SessionRegisterer implements Runnable {
        private SessionRegistry sessionregistry;
        private int nIterations;
        private Set sessionList;
        private Object principal;

        public SessionRegisterer(Object principal, SessionRegistry sessionregistry, int nIterations, Set sessionList) {
            this.sessionregistry = sessionregistry;
            this.nIterations = nIterations;
            this.sessionList = sessionList;
            this.principal = principal;
        }

        public void run() {
            for (int i=0; i < nIterations && !errorOccurred; i++) {
                String sessionId = Integer.toString(i);
                sessionList.add(sessionId);
                try {
                    sessionregistry.registerNewSession(sessionId,principal);
                    pause(20);
                    Thread.yield();
                } catch(Exception e) {
                    e.printStackTrace();
                    errorOccurred = true;
                }
            }
        }
    }

    private static class SessionRegistryReader implements Runnable {
        private SessionRegistry sessionRegistry;
        private Object principal;

        public SessionRegistryReader(Object principal, SessionRegistry sessionregistry) {
            this.sessionRegistry = sessionregistry;
            this.principal = principal;
        }

        public void run() {
            while (!errorOccurred) {
                try {
                    sessionRegistry.getAllSessions(principal, false);
                    sessionRegistry.getAllPrincipals();
                    sessionRegistry.getAllSessions(principal, true);
                    Thread.yield();
                } catch (Exception e) {
                    e.printStackTrace();
                    errorOccurred = true;
                }
            }
        }
    }

    private static class SessionRemover implements Runnable {
        private SessionRegistry sessionregistry;
        private Set sessionList;
        private String name;

        public SessionRemover(String name, SessionRegistry sessionregistry, Set sessionList) {
            this.name = name;
            this.sessionregistry = sessionregistry;
            this.sessionList = sessionList;
        }

        public void run() {
            boolean finished = false;

            while (!finished && !errorOccurred) {
                if (sessionList.isEmpty()) {
                    finished = true;
                    // List of sessions appears to be empty but give it a chance to fill up again
                    System.out.println(name + ": Session list empty. Waiting.");
                    pause(500);
                }

                Object[] sessions = sessionList.toArray();

                if (sessions.length > 0) {
                    finished = false;
                    String sessionId = (String) sessions[0];
//                    System.out.println(name + ": removing " + sessionId);
                    try {
                        sessionregistry.removeSessionInformation(sessionId);

                        pause(rnd.nextInt(100));

                        sessionList.remove(sessionId);
                        Thread.yield();
                    } catch (Exception e) {
                        e.printStackTrace();
                        errorOccurred = true;
                    }
                }
            }
        }
    }

    private static void pause(int length) {
        try {
            Thread.sleep(length);
        } catch (InterruptedException ignore) {}
    }
}
