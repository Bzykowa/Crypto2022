import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

public class TimingAttack {

    private NaiveRSA rsa;
    private SecureRandom random = new SecureRandom();
    private ArrayList<Third<Long, Integer, Integer>> setY = new ArrayList<>();
    private ArrayList<Third<Long, Integer, Integer>> setZ = new ArrayList<>();

    public TimingAttack(NaiveRSA rsa) {
        this.rsa = rsa;
    }

    public ArrayList<Third<Long, Integer, Integer>> getSetZ() {
        return setZ;
    }

    public ArrayList<Third<Long, Integer, Integer>> getSetY() {
        return setY;
    }

    private BigInteger genY() {

        BigInteger max = iroot(rsa.getN(), 3);
        int maxSize = max.bitLength();
        int randBitSize = random.nextInt(1, maxSize);

        BigInteger y = new BigInteger(randBitSize, random);

        return y.pow(3).compareTo(rsa.getN()) == -1 ? y : genY();

    }

    private BigInteger genZ() {

        BigInteger min = iroot(rsa.getN(), 3);
        BigInteger max = rsa.getN().sqrt();
        int minSize = min.bitLength();
        int maxSize = max.bitLength();
        int randBitSize = random.nextInt(minSize, maxSize);

        BigInteger z = new BigInteger(randBitSize, random);

        return z.pow(3).compareTo(rsa.getN()) == 1 && z.pow(2).compareTo(rsa.getN()) == -1 ? z : genZ();
    }

    private BigInteger iroot(BigInteger k, int n) {
        BigInteger k1 = k.subtract(BigInteger.ONE);
        BigInteger s = BigInteger.valueOf(n + 1);
        BigInteger u = BigInteger.valueOf(n);
        while (u.compareTo(s) == -1) {
            s = u;
            u = u.multiply(k1).add(BigInteger.valueOf(n));
        }
        return s;
    }

    public void genTestSets(int size) {
        setY = new ArrayList<>();
        setZ = new ArrayList<>();

        for (int i = 0; i < size; i++) {
            BigInteger y = genY();
            BigInteger z = genZ();

            BigInteger temp = rsa.enc(y);
            long xY = decryptTimer(temp);
            int rY = rsa.getReductions();
            int hY = rsa.getH();

            temp = rsa.enc(z);
            long xZ = decryptTimer(temp);
            int rZ = rsa.getReductions();
            int hZ = rsa.getH();

            setY.add(new Third<Long, Integer, Integer>(xY, rY, hY));
            setZ.add(new Third<Long, Integer, Integer>(xZ, rZ, hZ));
        }
    }

    public long decryptTimer(BigInteger c) {
        long start = System.nanoTime();
        rsa.dec(c);
        long end = System.nanoTime();
        return end - start;
    }

    public void test(){
        Third<Long,Long,Long> totalY = new Third<Long,Long,Long>(Long.valueOf(0),Long.valueOf(0), Long.valueOf(0));
        Third<Long,Long,Long> totalZ = new Third<Long,Long,Long>(Long.valueOf(0),Long.valueOf(0), Long.valueOf(0));



        for(int i = 0; i < setY.size(); i++){
            totalY.x += setY.get(i).x;
            totalY.r += setY.get(i).r;
            totalY.h += setY.get(i).h;
        }
        for(int i = 0; i < setZ.size(); i++){
            totalZ.x += setZ.get(i).x;
            totalZ.r += setZ.get(i).r;
            totalZ.h += setZ.get(i).h;
        }
       
        Third<Long,Long,Long> avgY = new Third<Long,Long,Long>(totalY.x/setY.size(),totalY.r/setY.size(), totalY.h/setY.size());
        Third<Long,Long,Long> avgZ = new Third<Long,Long,Long>(totalZ.x/setY.size(),totalZ.r/setY.size(), totalZ.h/setY.size());

        long avgSquareTime = avgY.x / avgY.h;
        long avgMultiplyTime = (avgZ.x - avgY.x)/avgZ.r;

        System.out.println("avg Y: "+ avgY.x +"; avg reds: "+ avgY.r+"; avg hs: "+ avgY.h);
        System.out.println("avg Z: "+ avgZ.x +"; avg reds: "+ avgZ.r+"; avg hs: "+ avgZ.h);

        System.out.println("avg x^2: "+avgSquareTime);
        System.out.println("avg c*x: "+avgMultiplyTime);

        System.out.println(rsa.getDBinary());


    }

}
