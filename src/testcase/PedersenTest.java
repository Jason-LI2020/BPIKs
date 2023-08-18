package testcase;

import com.okx.ecdsa.utils.Pedersen;
import java.math.BigInteger;

public class PedersenTest {
    public static void main(String[] args) {
        Pedersen pedersen = new Pedersen();
        pedersen.setup(1024);
        System.out.println("pedersen.n.len:"+ pedersen.n.toString(2).length());

        BigInteger x1 = pedersen.getRandomNumber(256);
        BigInteger r1 = pedersen.getRandomNumber(256);

        BigInteger commit1 = pedersen.commit(x1, r1);
        System.out.println("commit:"+commit1);

        Boolean open1 = pedersen.open(x1, r1, commit1);
        System.out.println("open:"+open1);


        BigInteger x2 = pedersen.getRandomNumber(256);
        BigInteger r2 = pedersen.getRandomNumber(256);

        BigInteger commit2 = pedersen.commit(x2, r2);
        System.out.println("commit:"+commit2);

        Boolean open2 = pedersen.open(x2, r2, commit2);
        System.out.println("open:"+open2);

        BigInteger x = x1.add(x2).mod(pedersen.n);
        BigInteger r = r1.add(r2).mod(pedersen.n);

        BigInteger commit = pedersen.add(commit1, commit2);
        Boolean open = pedersen.open(x, r, commit);
        System.out.println("open:"+open);








    }





}
