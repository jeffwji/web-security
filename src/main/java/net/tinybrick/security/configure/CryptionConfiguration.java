package net.tinybrick.security.configure;

import net.tinybrick.security.authentication.filter.tools.IEncryptionKeyManager;
import net.tinybrick.security.authentication.filter.tools.IEncryptionManager;
import net.tinybrick.security.authentication.filter.tools.RsaEncryptionKeyManager;
import net.tinybrick.security.authentication.filter.tools.RsaEncryptionManager;
import org.apache.commons.codec.DecoderException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.*;

/**
 * Created by ji.wang on 2017-07-28.
 */
@EnableAutoConfiguration
@Configuration
public class CryptionConfiguration {
    final Logger logger = LogManager.getLogger(this.getClass());

    @Value("${authentication.filter.secure.public_key_file:}") String publicKeyFileName;
    @Value("${authentication.filter.secure.private_key_file:}") String privateKeyFileName;
    @Bean
    public IEncryptionKeyManager encryptionKeyManager() throws IOException, DecoderException {
        IEncryptionKeyManager encryptionKeyManager = null;

        try {
            if((null != publicKeyFileName && publicKeyFileName.trim().length() > 0)
                    && (null != privateKeyFileName && privateKeyFileName.trim().length() > 0)) {
                InputStream publicKeyInput =  new FileInputStream(new File(publicKeyFileName));
                InputStream privateKeyInput = new FileInputStream(new File(privateKeyFileName));

                encryptionKeyManager = new RsaEncryptionKeyManager(publicKeyInput, privateKeyInput);
            }
            else {
                logger.warn("No key file defined. a default one has been created.");
                encryptionKeyManager = new RsaEncryptionKeyManager();
            }
        }
        catch(FileNotFoundException e){
            logger.error("No EncryptionKeyManager instance has been found. a default one has been created.", e);
            throw e;
        }

        return encryptionKeyManager;
    }

    @Bean
    public IEncryptionManager encryptionManager() throws Exception {
        IEncryptionManager encryptionManager = new RsaEncryptionManager(encryptionKeyManager());

        return encryptionManager;
    }
}
