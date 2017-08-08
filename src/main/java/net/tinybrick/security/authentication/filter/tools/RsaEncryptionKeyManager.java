package net.tinybrick.security.authentication.filter.tools;

import net.tinybrick.utils.crypto.Codec;
import net.tinybrick.utils.crypto.RSA;
import org.apache.commons.codec.DecoderException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

/**
 * Created by ji.wang on 2017-05-11.
 */
public class RsaEncryptionKeyManager implements IEncryptionKeyManager{
    Logger logger = LogManager.getLogger(this.getClass());
    static int default_keyLength=1024;

    byte[] publicKey = null;
    byte[] privateKey = null;

    public RsaEncryptionKeyManager() {
    }

    public RsaEncryptionKeyManager(InputStream  publicKeyInput, InputStream privateKeyFileName) throws IOException, DecoderException {
        publicKey = getByteFromInput(publicKeyInput);
        privateKey = getByteFromInput(privateKeyFileName);
    }

    protected byte[] getByteFromInput(InputStream in) throws IOException, DecoderException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        return Codec.fromBas64(reader.readLine());
    }

    public RsaEncryptionKeyManager(String publicKeyFileName, String privateKeyFileName) throws IOException, DecoderException {
        if((null != publicKeyFileName && publicKeyFileName.trim().length() > 0)
            && (null != privateKeyFileName && privateKeyFileName.trim().length() > 0)) {
            publicKey = Codec.fromBas64(new String(readFile(publicKeyFileName)));
            privateKey = Codec.fromBas64(new String(readFile(privateKeyFileName)));
        }
    }

    protected byte[] readFile(String filePath) throws IOException {
        Path fileLocation = Paths.get(filePath);
        byte[] data = Files.readAllBytes(fileLocation);
        return data;
    }

    public byte[] getEncryptKey() {
        if(null == publicKey || publicKey.length == 0) {
            try {
                byte[][] keys = RSA.generateKeyPair(default_keyLength);
                publicKey = keys[0];
                privateKey = keys[1];
            } catch (NoSuchAlgorithmException e) {
                logger.error(e.getMessage(), e);
            }
        }
        return publicKey;
    }

    public byte[] getDecryptKey() {
        if(null == privateKey || privateKey.length == 0) {
            try {
                byte[][] keys = RSA.generateKeyPair(default_keyLength);
                publicKey = keys[0];
                privateKey = keys[1];
            } catch (NoSuchAlgorithmException e) {
                logger.error(e.getMessage(), e);
            }
        }
        return privateKey;
    }
}
