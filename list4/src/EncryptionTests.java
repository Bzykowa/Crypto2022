import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

public class EncryptionTests {

    @Test
    public void encryptCBCTest()
            throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException,
            NoSuchPaddingException {

        SecretKey key = AESEncryption.generateKey(AESEncryption.DEFAULT_KEY_LENGTH);
        IvParameterSpec ivParameterSpec = AESEncryption.generateIv();
        // Enter full path accordingly to the enviroment
        File inputFile = new File("C:\\Users\\k.bak\\OneDrive - Veritas\\Pulpit\\Crypto\\test\\1.txt");
        File encryptedFile = new File("C:\\Users\\k.bak\\OneDrive - Veritas\\Pulpit\\Crypto\\test\\1.txt.enc");
        File decryptedFile = new File("C:\\Users\\k.bak\\OneDrive - Veritas\\Pulpit\\Crypto\\test\\1.txt.dec");
        AESEncryption.encryptFileCBC(key, ivParameterSpec, inputFile, encryptedFile);
        AESEncryption.decryptFileCBC(key, ivParameterSpec, encryptedFile, decryptedFile);
        assertTrue("Files match!", FileUtils.contentEquals(inputFile, decryptedFile));
    }

    @Test
    public void encryptGCMTest()
            throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException,
            NoSuchPaddingException {

        SecretKey key = AESEncryption.generateKey(AESEncryption.DEFAULT_KEY_LENGTH);
        GCMParameterSpec iv = AESEncryption.generateGCMParameter();
        // Enter full path accordingly to the enviroment
        File inputFile = new File("C:\\Users\\k.bak\\OneDrive - Veritas\\Pulpit\\Crypto\\test\\1.txt");
        File encryptedFile = new File("C:\\Users\\k.bak\\OneDrive - Veritas\\Pulpit\\Crypto\\test\\1.txt.enc");
        File decryptedFile = new File("C:\\Users\\k.bak\\OneDrive - Veritas\\Pulpit\\Crypto\\test\\1.txt.dec");
        AESEncryption.encryptFileGCM(key, iv, inputFile, encryptedFile);
        AESEncryption.decryptFileGCM(key, iv, encryptedFile, decryptedFile);
        assertTrue("Files match!", FileUtils.contentEquals(inputFile, decryptedFile));
    }
}
