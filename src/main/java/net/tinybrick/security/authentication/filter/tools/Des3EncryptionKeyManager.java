package net.tinybrick.security.authentication.filter.tools;

import net.tinybrick.security.authentication.filter.EnhancedBasicAuthenticationFilter;

import java.util.UUID;

/**
 * Created by ji.wang on 2017-05-11.
 */
public class Des3EncryptionKeyManager implements IEncryptionKeyManager {
    String key;

    public void setKey(String key) {
        this.key = key;
    }

    public String getEncryptKey() {
        if (null == key || key.length() == 0) {
            key = UUID.randomUUID().toString();
            key = key.length() > 24 ? key.substring(0, 24)
                    : key;
        }
        return key;
    }

    public String getDecryptKey() {
        return key;
    }
}
