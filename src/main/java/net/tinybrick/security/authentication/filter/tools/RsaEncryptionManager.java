package net.tinybrick.security.authentication.filter.tools;

import net.tinybrick.security.authentication.filter.EnhancedBasicAuthenticationFilter;
import net.tinybrick.utils.crypto.Codec;
import net.tinybrick.utils.crypto.RSA;
import org.apache.log4j.Logger;

/**
 * Created by ji.wang on 2017-05-11.
 */
public class RsaEncryptionManager implements EnhancedBasicAuthenticationFilter.IEncryptionManager {
    Logger logger = Logger.getLogger(this.getClass());
    EnhancedBasicAuthenticationFilter.IEncryptionKeyManager keyManager = null;

    public RsaEncryptionManager(EnhancedBasicAuthenticationFilter.IEncryptionKeyManager keyManager) throws Exception {
        this.keyManager = keyManager;
    }

    @Override
    public String encrypt(String str) throws Exception {
        String res = Codec.toBase64(RSA.encrypt(str.getBytes(), (byte[])keyManager.getEncryptKey()));
        logger.debug("Input has been encrypted to " + res);
        return res;
    }

    @Override
    public String decrypt(String str) throws Exception {
        String res = new String(RSA.decrypt(Codec.fromBas64(str),  (byte[])keyManager.getDecryptKey()));
        logger.debug(str + " has been decrypted");
        return res;
    }
}
