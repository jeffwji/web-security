package net.tinybrick.security.authentication.filter.tools;

/**
 * Created by ji.wang on 2017-06-06.
 */
public interface IEncryptionManager {
    String encrypt(String str) throws Exception;
    String decrypt(String str) throws Exception;
}
