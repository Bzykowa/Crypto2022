import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class AESEncryption {

    private static final String CBC_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String GCM_ALGORITHM = "AES/GCM/NoPadding";

    private static final int CBC_IV_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    public static final int DEFAULT_KEY_LENGTH = 256;

    private static final String IV_FILENAME = "iv.txt";

    /**
     * Generate AES key.
     * 
     * @param n Bit length of the key
     * @return Generated AES SecretKey
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    /**
     * Generate IV for the AES-CBC encryption.
     * 
     * @return IvParameterSpec containing generated IV
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[CBC_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Generate IV for the AES-GCM encryption.
     * 
     * @return GCMParameterSpec containing generated IV
     */
    public static GCMParameterSpec generateGCMParameter() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return new GCMParameterSpec(GCM_TAG_LENGTH, iv);

    }

    /**
     * Encrypt a file using AES encryption in CBC Mode.
     * 
     * @param key        SecretKey for encryption
     * @param iv         Initialization vector for the encryption
     * @param inputFile  File to be encrypted
     * @param outputFile Encrypted file
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void encryptFileCBC(SecretKey key, IvParameterSpec iv,
            File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        processFiles(cipher, inputStream, outputStream);
    }

    /**
     * Encrypt a file using AES encryption in GCM Mode.
     * 
     * @param key        SecretKey for encryption
     * @param iv         Initialization vector for the encryption
     * @param inputFile  File to be encrypted
     * @param outputFile Encrypted file
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void encryptFileGCM(SecretKey key, GCMParameterSpec iv,
            File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        processFiles(cipher, inputStream, outputStream);
    }

    /**
     * Decrypt a file using AES encryption in CBC Mode.
     * 
     * @param key        SecretKey for decryption
     * @param iv         Initialization vector for the decryption
     * @param inputFile  File to be decrypted
     * @param outputFile Decrypted file
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void decryptFileCBC(SecretKey key, IvParameterSpec iv,
            File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        processFiles(cipher, inputStream, outputStream);
    }

    /**
     * Decrypt a file using AES encryption in GCM Mode.
     * 
     * @param key        SecretKey for decryption
     * @param iv         Initialization vector for the decryption
     * @param inputFile  File to be decrypted
     * @param outputFile Decrypted file
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void decryptFileGCM(SecretKey key, GCMParameterSpec iv,
            File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(GCM_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        processFiles(cipher, inputStream, outputStream);
    }

    /**
     * Apply cipher to the input file for encryption/decryption and save the result
     * to the output file.
     * 
     * @param cipher       Initialized cipher
     * @param inputStream  Initialized FileStream for the input file
     * @param outputStream Initialized FileStream for the output file
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private static void processFiles(Cipher cipher, FileInputStream inputStream, FileOutputStream outputStream)
            throws IOException, IllegalBlockSizeException, BadPaddingException {

        // Work in 64 byte chunks
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    /**
     * Save IV to a file to allow decryption later.
     * 
     * @param iv IV to save to a file
     * @throws IOException
     */
    public static void saveIV(byte[] iv) throws IOException {
        //
        FileOutputStream ivOutput = new FileOutputStream(IV_FILENAME);
        ivOutput.write(iv);
        ivOutput.close();
    }

}
