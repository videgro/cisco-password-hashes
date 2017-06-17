package net.videgro.poc.cisco_pw_hashes;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lambdaworks.crypto.SCrypt;

/**
 * Calculate a Cisco Type 9 password hash
 */
public class CiscoPasswordHashType09 extends CiscoPasswordHash {
    private static final Logger LOGGER = LoggerFactory.getLogger(CiscoPasswordHashType08.class);

    /**
     * CPU cost
     */
    private static final int N = 16384;

    /**
     * Memory cost
     */
    private static final int R = 1;

    /**
     * Parallelization
     */
    private static final int P = 1;

    public String generateHash(final String password, final String salt) {
        String result = null;
        byte[] derived = null;
        try {
            derived = SCrypt.scrypt(password.getBytes(CiscoPasswordHash.UTF8), salt.getBytes(CiscoPasswordHash.UTF8), N, R, P, CiscoPasswordHash.LEN);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            LOGGER.error("generateHash", e);
        }

        if (derived != null) {
            result = String.format("$9$%s$%s", salt, base64_wpa(derived));
        }

        LOGGER.trace("Generated Cisco Type 9 password hash for password: {}, with salt: {}, hash: {}", password, salt, result);
        return result;
    }
}
