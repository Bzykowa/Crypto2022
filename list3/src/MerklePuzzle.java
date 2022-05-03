import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MerklePuzzle {

    // Max 31 bit due to limit on indexing in Java (it has to be in the int range)
    private int n;
    private ArrayList<SecretKey> keys;
    private ArrayList<byte[]> messages;
    private SecretKey sessionKey;
    private AESEncryption enc;

    private final byte[] messagePrefix = "A message prefix".getBytes();

    public MerklePuzzle(int n) {
        this.n = n;
        enc = new AESEncryption();
    }

    public MerklePuzzle(int n, IvParameterSpec iv) {
        this.n = n;
        enc = new AESEncryption(iv);
    }

    public IvParameterSpec getIv() {
        return enc.getIv();
    }

    public void setSessionKey(int id) {
        sessionKey = keys.get(id);
        System.out.println("Secret key at idx: " + id + " is " + Arrays.toString(sessionKey.getEncoded()));
    }

    public ArrayList<byte[]> preparePuzzles() {
        keys = new ArrayList<>();
        messages = new ArrayList<>();

        for (int i = 0; i < n; i++) {

            byte[] id = intToByteArray(i);
            String pKey = String.valueOf(new SecureRandom().nextInt(n));

            try {
                SecretKey key = enc.generateKey();
                SecretKey puzzleKey = enc.generateKey(pKey, pKey);

                keys.add(key);

                // Combine messagePrefix, id and key into one message
                byte[] message = new byte[messagePrefix.length + id.length + key.getEncoded().length];
                ByteBuffer bb = ByteBuffer.wrap(message);
                bb.put(messagePrefix);
                bb.put(id);
                bb.put(key.getEncoded());

                messages.add(enc.encrypt(bb.array(), puzzleKey));
            } catch (Exception e) {
                // Something happened
                e.printStackTrace();
            }

        }

        Collections.shuffle(messages);
        return messages;
    }

    public int decryptRandomPuzzle(ArrayList<byte[]> puzzles) {

        byte[] secret = puzzles.get(new SecureRandom().nextInt(puzzles.size()));
        int id = -1;

        System.out.println("Brute forcing the secret key in a random puzzle.");
        for (int i = 0; i < n; i++) {

            try {
                SecretKey k = enc.generateKey(String.valueOf(i), String.valueOf(i));
                byte[] message = enc.decrypt(secret, k);
                byte[] prefix = Arrays.copyOfRange(message, 0, 16);

                // Correct key
                if (Arrays.equals(prefix, messagePrefix)) {
                    id = byteArrayToInt(Arrays.copyOfRange(message, 16, 32));
                    sessionKey = new SecretKeySpec(Arrays.copyOfRange(message, 32, message.length), "AES");

                    System.out.println("Found the secret key.");
                    System.out.println("id: " + id + ", key: " + Arrays.toString(sessionKey.getEncoded()));
                    return id;
                }

            } catch (BadPaddingException ex) {
                // All my homies hate padding
            } catch (Exception e) {
                // Something happened
                e.printStackTrace();
            }
        }

        return id;

    }

    public long messageMemory() {
        long memory = 0;
        if (messages == null) {
            return memory;
        }
        for (byte[] message : messages) {
            memory += message.length;
        }
        return memory;
    }

    public long keysMemory() {
        long memory = 0;
        if (keys == null) {
            return memory;
        }
        for (SecretKey key : keys) {
            memory += key.getEncoded().length;
        }
        return memory;
    }

    private byte[] intToByteArray(int input) {
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putInt(input);
        return bb.array();
    }

    private int byteArrayToInt(byte[] input) {
        ByteBuffer bb = ByteBuffer.wrap(input);
        return bb.getInt();
    }
}
