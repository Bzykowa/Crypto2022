import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CPADistinguisher {

    private SecretKey key;
    private IvParameterSpec iv;
    private IvParameterSpec prevIV;
    private byte[] preparedPT;
    private boolean bitCheck;

    /**
     * Initialize the oracle.
     * 
     * @param key SecretKey of the oracle
     * @param iv  Initial initialization vector of this oracle
     */
    public CPADistinguisher(SecretKey key, IvParameterSpec iv) {
        this.key = key;
        this.iv = iv;
    }

    /**
     * Test the CPA on oracle with parameters specified in this distinguisher.
     * 
     * @return true if guessed correctly; false otherwise
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public boolean testCPA() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        // Generate attack values
        byte[] randomMessage = new byte[16];
        new SecureRandom().nextBytes(randomMessage);
        byte[] testCT = oracleQuery(randomMessage);

        // Generate a random message to test against
        new SecureRandom().nextBytes(randomMessage);

        byte[] challenge = oracleChallenge(preparedPT, randomMessage);

        // Guess which message was encrypted
        boolean guessedCheck = Arrays.equals(challenge, testCT) ? false : true;
        return bitCheck == guessedCheck ? true : false;

    }

    /**
     * Query the oracle and generate next plain text value that will yield the same
     * cipher text value as returned.
     * 
     * @param message A plain text to encrypt by the oracle
     * @return Cipher text of sumbitted message
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private byte[] oracleQuery(byte[] message) throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte ct[] = AESEncryption.encryptMessageCBC(key, iv, message);
        updateIV();
        preparedPT = xorByteArrays(xorByteArrays(message, prevIV.getIV()), iv.getIV());
        return ct;
    }

    /**
     * Challenge the oracle for the two messages.
     * 
     * @param message0 First message to choose from
     * @param message1 Second message to choose from
     * @return Cipher text for the randomly chosen plain text between message0 and
     *         message1
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private byte[] oracleChallenge(byte[] message0, byte[] message1)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        bitCheck = new SecureRandom().nextBoolean();
        byte[] ct = !bitCheck ? AESEncryption.encryptMessageCBC(key, iv, message0)
                : AESEncryption.encryptMessageCBC(key, iv, message1);
        updateIV();
        return ct;
    }

    /**
     * Update IV values for the oracle and the distinguisher.
     */
    private void updateIV() {
        prevIV = iv;
        iv = AESEncryption.generateVulnerableIv(iv.getIV());
    }

    /**
     * Apply bitwise XOR to two byte[] of the same length
     * 
     * @param arr1
     * @param arr2
     * @return byte[] arr3 with xored arr1 and arr2
     */
    private byte[] xorByteArrays(byte[] arr1, byte[] arr2) {

        if (arr1.length != arr2.length)
            throw new IllegalArgumentException("Arrays have a different length");

        byte[] arr3 = new byte[arr1.length];
        int i = 0;
        for (byte b : arr1) {
            arr3[i] = (byte) (b ^ arr2[i++]);
        }
        return arr3;
    }

}
