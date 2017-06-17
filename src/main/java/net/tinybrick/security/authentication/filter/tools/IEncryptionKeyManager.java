package net.tinybrick.security.authentication.filter.tools;

/**
 * Created by ji.wang on 2017-06-06.
 */
public interface IEncryptionKeyManager {
    Object getEncryptKey();
    Object getDecryptKey();
}
