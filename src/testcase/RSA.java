package testcase;

import com.vhklabs.ecdsa.utils.HashUtil;
import java.math.BigInteger;

public class RSA {

    public static void main(String[] args) {
    BigInteger ONE =  new BigInteger("1",16);
    BigInteger secp256key = new BigInteger("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",16);

    System.out.println("secp256key: " + secp256key);

    BigInteger hashP = new BigInteger(HashUtil.getSHA(secp256key.toString(16), "SHA-512"),16);
    BigInteger p = hashP.nextProbablePrime();
    System.out.println("p: " + p);

    BigInteger hashQ = new BigInteger(HashUtil.getSHA(hashP.toString(16), "SHA-512"),16);
    BigInteger q = hashQ.nextProbablePrime();
    System.out.println("q: " + q);

    BigInteger p1 = p.subtract(ONE);
    BigInteger q1 = q.subtract(ONE);
    BigInteger n = p.multiply(q);
    BigInteger phi = p1.multiply(q1);
    BigInteger pubkey = new BigInteger("65537");
    BigInteger prikey = pubkey.modInverse(phi);

    System.out.println("n: " + n);
    System.out.println("pubkey: " + pubkey);
    System.out.println("prikey: " + prikey);


    BigInteger message = new BigInteger("999", 16);

    BigInteger encrypedMsg = message.modPow(pubkey, n);

    BigInteger decryptedMsg = encrypedMsg.modPow(prikey, n);

    System.out.println("message: " + message);
    System.out.println("encrypedMsg: " + encrypedMsg);
    System.out.println("decryptedMsg: " + decryptedMsg);



    }





}



