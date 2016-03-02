/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.scrypt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.bouncycastle.crypto.generators.SCrypt;


/**
 * Implementation of PasswordEncoder that uses the SCrypt hashing function. Clients
 * can optionally supply a cpu cost parameter, a memory cost parameter and a parallelization parameter.
 * 
 * @author Shazin Sadakath
 *
 */
public class SCryptPasswordEncoder implements PasswordEncoder {
    
    private final Log logger = LogFactory.getLog(getClass());
    
    private final int cpuCost;
    
    private final int memoryCost;
    
    private final int parallelization;
    
    private final byte[] saltBytes;
    
    public SCryptPasswordEncoder() {
        this(new String(KeyGenerators.secureRandom().generateKey()), 16384, 8, 1);
    }
    
    /**
     * @param salt value for the algorithm
     * @param cpu cost of the algorithm. must be power of 2 greater than 1
     * @param memory cost of the algorithm
     * @param parallelization of the algorithm
     */
    public SCryptPasswordEncoder(CharSequence salt, int cpuCost, int memoryCost, int parallelization) {
        if(salt == null || salt.length() == 0) {
            throw new IllegalArgumentException("Secret is required to get salt value");
        }
        if (cpuCost <= 1) {
            throw new IllegalArgumentException("Cpu cost parameter must be > 1.");
        }
        if (memoryCost == 1 && cpuCost > 65536) {
            throw new IllegalArgumentException("Cpu cost parameter must be > 1 and < 65536.");
        }
        if (memoryCost < 1) {
            throw new IllegalArgumentException("Memory cost must be >= 1.");
        }
        int maxParallel = Integer.MAX_VALUE / (128 * memoryCost * 8);
        if (parallelization < 1 || parallelization > maxParallel) {
            throw new IllegalArgumentException("Parallelisation parameter p must be >= 1 and <= " + maxParallel
                + " (based on block size r of " + memoryCost + ")");
        }
        
        this.saltBytes = Utf8.encode(salt);
        this.cpuCost = cpuCost;
        this.memoryCost = memoryCost;
        this.parallelization = parallelization;
    }

	@Override
	public String encode(CharSequence rawPassword) {
        return new String(Hex.encode(SCrypt.generate(Utf8.encode(rawPassword), saltBytes, cpuCost, memoryCost, parallelization, saltBytes.length)));
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if(encodedPassword == null || encodedPassword.length() == 0) {
		    logger.warn("Empty encoded password");
		    return false;		           
		}
		final String actualPassword = encode(rawPassword);
		if(actualPassword.length() != encodedPassword.length()) {
		    return false;
		}
		int matches = 0;
		for(int i=0;i<actualPassword.length();i++) {
		    matches = actualPassword.charAt(i) ^ encodedPassword.charAt(i);
		}
		
		return matches == 0;
	}
	
}
