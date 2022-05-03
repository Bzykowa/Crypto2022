import java.util.ArrayList;
import java.util.Scanner;

public class App {

    public static void main(String[] args) throws Exception {

        System.out.println("Enter n value (less than 32)");
        Scanner in = new Scanner(System.in);
        String input = in.nextLine();
        in.close();

        int n = Integer.valueOf(input);
        int N = (int) Math.pow(2, n);

        // Initiate communication actors
        MerklePuzzle Alice = new MerklePuzzle(N);
        MerklePuzzle Bob = new MerklePuzzle(N, Alice.getIv());

        // Time puzzle generation
        System.out.println("Alice generates " + N + " puzzles...");
        long start = System.currentTimeMillis();
        ArrayList<byte[]> puzzles = Alice.preparePuzzles();
        long end = System.currentTimeMillis();
        System.out.println("Alice sends " + N + " puzzles to Bob");

        long puzzleGenTime = end - start;

        // Time decrypting a random puzzle
        System.out.println("Bob receives the puzzles.");
        start = System.currentTimeMillis();
        int id = Bob.decryptRandomPuzzle(puzzles);
        end = System.currentTimeMillis();

        long decryptingPuzzleTime = end - start;

        System.out.println("Alice received id = " + id + " from Bob");
        Alice.setSessionKey(id);

        System.out.println("Puzzle memory usage:");
        System.out.println("Messages: " + Alice.messageMemory() + " bytes.");
        System.out.println("Keys: " + Alice.keysMemory() + " bytes.");

        System.out.println("Times:");
        System.out.println("Puzzle generation: " + puzzleGenTime + " ms.");
        System.out.println("Puzzle decrypting: " + decryptingPuzzleTime + " ms.");

    }
}
