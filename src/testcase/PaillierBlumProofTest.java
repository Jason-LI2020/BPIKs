package testcase;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.utils.Pedersen;

import bls12381.BLS12381.BIG;

import com.okx.ecdsa.utils.PaillierBlumProof;
import com.okx.ecdsa.utils.NumericUtil;

import com.okx.ecdsa.Point;

import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;

// Prover claims that N is a Paillier Blum modulus, i.e. gcd(N, phi(N)) = 1, N = p * q, and p, q % 4 = 3
// https://eprint.iacr.org/2020/492.pdf, chapter 4.3
public class PaillierBlumProofTest {
        public static void main(String[] args) throws HomomorphicException{
        // set up
        PaillierBlumProof pail_blum_proof = new PaillierBlumProof();
        NumericUtil numericUtil = new NumericUtil();
        int security = 256;
        BigInteger p = numericUtil.safePrime(security);
        BigInteger q = numericUtil.safePrime(security);
        BigInteger N = p.multiply(q);

        // prove
        BigInteger w = numericUtil.getRandomNumber(N.bitLength()).mod(N);
        while( pail_blum_proof.jacobi(w, N) != -1){
            w = numericUtil.getRandomNumber(N.bitLength()).mod(N);
        };

        BigInteger root = BigInteger.ZERO;
        BigInteger a = BigInteger.ZERO;
        BigInteger b = BigInteger.ZERO;
        BigInteger r = numericUtil.getRandomNumber(N.bitLength()).mod(N);

        BigInteger p_inv = p.modInverse(q);
        BigInteger q_inv = q.modInverse(p);
        BigInteger[] result = pail_blum_proof.getQuaticSqrt(N, p, q, p_inv, q_inv, w, r, root, a, b);

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger pow = N.modInverse(phi);
        BigInteger z = r.modPow(pow, N);

        // verify
        // assert (N is an odd composite number)
        if (N.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0 || N.isProbablePrime(100)) {
            System.out.println("N should be an odd composite number");
            return;
        }

        // assert (z^N = r mod N)
        if (z.modPow(N, N).compareTo(r) != 0) {
            System.out.println("z^N != r mod N");
            return;
        }

        // c = (-1)^a * w^b * r mod N
        // assert (x^4 = c mod N)
        BigInteger c = BigInteger.ONE.negate().modPow(result[1], N).multiply(w.modPow(result[2], N)).multiply(r).mod(N);
        if (result[0].modPow(BigInteger.valueOf(4), N).compareTo(c) != 0) {
            System.out.println("x^4 != (-1)^a * w^b * r mod N");
            return;
        }

        System.out.println("verify success");

    }

}
