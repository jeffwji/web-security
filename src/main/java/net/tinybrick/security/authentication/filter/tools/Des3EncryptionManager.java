package net.tinybrick.security.authentication.filter.tools;

import net.tinybrick.utils.crypto.DES3;
import org.apache.log4j.Logger;

/**
 * Created by ji.wang on 2017-05-11.
 */
public class Des3EncryptionManager implements IEncryptionManager {
    Logger logger = Logger.getLogger(this.getClass());
    IEncryptionKeyManager keyManager = null;

    public Des3EncryptionManager(IEncryptionKeyManager keyManager) throws Exception {
        this.keyManager = keyManager;
    }

    @Override
    public String encrypt(String str) throws Exception {
        String res = DES3.encrypt(keyManager.getEncryptKey().toString(), str);
        logger.debug("Input has been encrypted to " + res);
        return res;
    }

    @Override
    public String decrypt(String str) throws Exception {
        String res = DES3.decrypt(keyManager.getEncryptKey().toString(), str);
        logger.debug(str + " has been decrypted to " + res);
        return res;
    }
}
