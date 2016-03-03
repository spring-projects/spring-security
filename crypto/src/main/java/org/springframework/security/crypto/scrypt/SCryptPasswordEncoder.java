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

import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
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
    
    private final int keyLength;
    
    private final BytesKeyGenerator saltGenerator;
    
    public SCryptPasswordEncoder() {
        this(16384, 8, 1, 32, 64);
    }
    
    /**
     * @param cpu cost of the algorithm. must be power of 2 greater than 1
     * @param memory cost of the algorithm
     * @param parallelization of the algorithm
     * @param key length for the algorithm
     * @param salt length
     */
    public SCryptPasswordEncoder(int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength) {
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
        if (keyLength < 1 || keyLength > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Key length must be >= 1 and <= "+Integer.MAX_VALUE);
        }
        if (saltLength < 1 || saltLength > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Salt length must be >= 1 and <= "+Integer.MAX_VALUE);
        }
        
        this.cpuCost = cpuCost;
        this.memoryCost = memoryCost;
        this.parallelization = parallelization;
        this.keyLength = keyLength;
        this.saltGenerator = KeyGenerators.secureRandom(saltLength);
    }

	@Override
	public String encode(CharSequence rawPassword) {	    
        return digest(rawPassword, saltGenerator.generateKey());
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if(encodedPassword == null || encodedPassword.length() < keyLength) {
		    logger.warn("Empty encoded password");
		    return false;		           
		}
		return decodeAndCheckMatches(rawPassword, encodedPassword);		
	}    
	
	private boolean decodeAndCheckMatches(CharSequence rawPassword, String encodedPassword) {
	    String[] parts = encodedPassword.split("\\$");

        if (parts.length != 4) {
            return false;
        }

        Decoder decoder = Base64.getDecoder();
        long params = Long.parseLong(parts[1], 16);        
        byte[] salt = decoder.decode(parts[2]);
        byte[] derived = decoder.decode(parts[3]);

        int cpuCost = (int) Math.pow(2, params >> 16 & 0xffff);
        int memoryCost = (int) params >> 8 & 0xff;
        int parallelization = (int) params & 0xff;

        byte[] generated = SCrypt.generate(Utf8.encode(rawPassword), salt, cpuCost, memoryCost, parallelization, keyLength);

        if (derived.length != generated.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < derived.length; i++) {
            result |= derived[i] ^ generated[i];
        }
        return result == 0;
	}
	
	private String digest(CharSequence rawPassword, byte[] salt) {	    
	    byte[] derived = SCrypt.generate(Utf8.encode(rawPassword), salt, cpuCost, memoryCost, parallelization, 32);

        String params = Long.toString(((int) (Math.log(cpuCost) / Math.log(2)) << 16L) | memoryCost << 8 | parallelization, 16);
        Encoder encoder = Base64.getEncoder();
        
        StringBuilder sb = new StringBuilder((salt.length + derived.length) * 2);
        sb.append("$").append(params).append('$');
        sb.append(encoder.encodeToString(salt)).append('$');
        sb.append(encoder.encodeToString(derived));

        return sb.toString();  
	}
	
}
