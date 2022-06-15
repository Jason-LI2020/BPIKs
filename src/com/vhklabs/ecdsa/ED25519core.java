package com.vhklabs.ecdsa;


import com.vhklabs.ecdsa.utils.Base58;
import com.vhklabs.ecdsa.utils.HEX;
import com.vhklabs.ecdsa.utils.HashUtil;

import java.math.BigInteger;

/**
 *  ED25519 CORE
 * @author Jason LI
 *  - MetaX
 */
public class ED25519core {
    static BigInteger ZERO = new BigInteger("0");
    static BigInteger ONE = new BigInteger("1");
    static BigInteger TWO = new BigInteger("2");
    static BigInteger THREE = new BigInteger("3");

    /**
     * ed25519 is Twisted Edwards curve with equation of
     * ```
     * ax² + y² = 1 + d * x² * y²
     * a = -1;
     * d = - (121665/121666)
     * −x² + y² = 1 − (121665/121666) * x² * y²
     * ```
     */

    private BigInteger a = new BigInteger("-1");
    // Equal to -121665/121666 over finite field.
    // Negative number is P - number, and division is invert(number, P)
    private BigInteger d = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");

    // Finite field, q = 2**255 - 19
    private BigInteger q= new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819943");
    // subgroup order, how many points ed25519 has, n = 2**252 + 27742317777372353535851937790883648493
    private BigInteger n= new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    // cofactor
    private BigInteger h= new BigInteger("8");

    //The Base Poing G 
    private Point G = new Point(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    private Point NEUTRAL_POINT = new Point(ZERO, ONE);






    /**
     * point add method 点加法
     * @param pointG
     * @param pointQ
     * @return
     */
    public Point add(Point pointG,Point pointQ){
        Point returnPoint = null;
        // if(pointG.equals(pointQ)){returnPoint = times2(pointG);}
        // else if (pointG.equals(NEUTRAL_POINT)){returnPoint = pointQ;}
        // else if (pointQ.equals(NEUTRAL_POINT)){returnPoint = pointG;}
        // else if (isInverse(pointG,pointQ)){returnPoint = Point.POINT_AT_INFINITY;}
        // else {
            BigInteger x1 = pointG.getX();
            BigInteger y1 = pointG.getY();
            BigInteger x2 = pointQ.getX();
            BigInteger y2 = pointQ.getY();

            // A = x1*y2 + y1*x2
            BigInteger A = (x1.multiply(y2).add(y1.multiply(x2))).mod(q);
            // B = 1 + d*x1*x2*y1*y2
            BigInteger B = (ONE.add(d.multiply(x1).multiply(x2).multiply(y1).multiply(y2))).mod(q);
            // pointX = A/B
            BigInteger pointX = A.multiply(B.modInverse(q)).mod(q);

            // C = y1*y2 - a*x1*x2
            BigInteger C = (y1.multiply(y2).add(a.multiply(x1).multiply(x2))).mod(q);
            // D = 1 - d*x1*x2*y1*y2
            BigInteger D = ONE.subtract(d.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).mod(q);
            // pointY = C/D
            BigInteger pointY = C.multiply(D.modInverse(q)).mod(q);


            // BigInteger s = pointQ.getY().subtract(pointG.getY()).mod(p).multiply((pointQ.getX().subtract(pointG.getX())).modInverse(p));
            // BigInteger pointX = s.multiply(s).subtract(pointG.getX()).subtract(pointQ.getX()).mod(p);
            // BigInteger pointY = (s.multiply(pointG.getX().subtract(pointX))).subtract(pointG.getY()).mod(p);
            returnPoint = new Point(pointX,pointY);
        // }

            BigInteger res = n.subtract(
                new BigInteger("121665").multiply(
                    new BigInteger("121666").modInverse(q)
                )
            ).mod(n);
            res = res.mod(n);
            System.out.println("res" + res);


            System.out.println("mod invert 121666");
            BigInteger mi = new BigInteger("121666").modInverse(q);
            System.out.println(mi);

            System.out.println("-121665/121666");
            BigInteger neg = new BigInteger("121665").multiply(mi);
            neg = neg.mod(q);
            System.out.println(neg);
















        return  returnPoint;
    }


























//     // =======================================================


//     /**
//      * 签名
//      * @author William Liu
//      * @param message 消息的hash
//      * @param privateKey
//      * @return
//      */
//     public String[] sign(String message,String privateKey){
//         String[] signature = new String[2];
//         BigInteger r, s;
//         do {

//             BigInteger k = new BigInteger(HashUtil.getSHA(Math.random() + System.currentTimeMillis() + "THHAhshjaYYHJSA^HGHSA", "SHA-256"), 16);
//             r = fastMultiply(k).getX().mod(p);
//             s = (new BigInteger(message, 16).add(new BigInteger(privateKey, 16).multiply(r))).multiply(k.modInverse(n)).mod(n);

//             //standrad bitcoin signature SIG is <r><s> concatenated together.
//             // We need to check s < N/2 where N is the curve order, .
//             // If s>N/2, then s = N-s
// //        if (n.divide(BigInteger.TWO).compareTo(s) < 0) {
// //            s = n.subtract(s);
// //        }

//             signature[0] = r.toString(16);
//             signature[1] = s.toString(16);

//         }while (isValidSignature(r,s));
//         return formatSign(signature);
//     }

//     public String[] signWithAssignedK(String message,String privateKey, BigInteger k){
//         String[] signature = new String[2];
//         BigInteger r, s;
//         do {

//             //BigInteger k = new BigInteger(HashUtil.getSHA(Math.random() + System.currentTimeMillis() + "THHAhshjaYYHJSA^HGHSA", "SHA-256"), 16);
//             r = fastMultiply(k).getX().mod(p);
//             s = (new BigInteger(message, 16).add(new BigInteger(privateKey, 16).multiply(r))).multiply(k.modInverse(n)).mod(n);

//             //standrad bitcoin signature SIG is <r><s> concatenated together.
//             // We need to check s < N/2 where N is the curve order, .
//             // If s>N/2, then s = N-s
// //        if (n.divide(BigInteger.TWO).compareTo(s) < 0) {
// //            s = n.subtract(s);
// //        }

//             signature[0] = r.toString(16);
//             signature[1] = s.toString(16);

//         }while (isValidSignature(r,s));
//         return formatSign(signature);
//     }

//     /**
//      * signature 补0
//      * @param signature
//      * @return
//      */
//     public static String[] formatSign(String[] signature) {
//         String[] sig= new String[2];
//         for(int i=0;i<sig.length;i++) {
//             if (signature[i].length() % 2 != 0) {
//                 sig[i] = "0" + signature[i];
//             }else {
//                 sig[i] = signature[i];
//             }
//         }

//         return sig;
//     }

//     /**
//      * 验证签名正确性，兼容Ethereum,符合BIP0062
//      * see https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
//      * @param r
//      * @param s
//      * @return
//      */
//     public boolean isValidSignature(BigInteger r,BigInteger s){
// //        boolean flag = false;
// //        String sS = s.toString(16);
// //        if(r.toString(16).length()==64 && s.toString(16).length()==64 ){
// //            flag = true;
// //        }

//         return n.divide(new BigInteger("2")).compareTo(s) < 0;
//     }


// //    public void sign(byte[] message,String privateKey,Point publicKeyPoint){
// //        BigInteger k = new BigInteger("6b99",16);
// //        r = fastMultiply(k).getX().mod(p);
// //        s = (new BigInteger(HEX.decode(message),16).add(new BigInteger(privateKey,16).multiply(r))).multiply(k.modInverse(n)).mod(n);
// //        System.out.println("r: "+r.toString() + " s: "+s.toString());
// //    }
// //
// //    public void signeth(byte[] message,String privateKey,Point publicKeyPoint){
// //        BigInteger k = new BigInteger("f17855954749dd1275ef93ce033f52c355feb3ee2ac070cc31bd57c195e3aff7",16);
// //        Point z = fastMultiply(k);
// //        r = z.getX().mod(p);
// //        s = new BigInteger(message).add(new BigInteger(privateKey,16).multiply(r)).multiply(k.modInverse(n)).mod(n);
// //        if(z.getY().mod(new BigInteger("2")).intValue() == 0){
// //            System.out.println("k: 0");
// //        }else {
// //            System.out.println("k: 1");
// //        }
// //        System.out.println("r: "+r.toString(16) + " s: "+s.toString(16));
// //    }

//     /**
//      * verify method
//      * @author William Liu
//      * @param message
//      * @param rS
//      * @param sS
//      * @param publicKeyPoint
//      */
//     public void verify(String message,String rS,String sS,Point publicKeyPoint){
//         BigInteger r = new BigInteger(rS,16);
//         BigInteger s = new BigInteger(sS,16);
//         BigInteger w = s.modInverse(n);
//         BigInteger u1 = w.multiply(new BigInteger(message,16)).mod(n);
//         BigInteger u2 = w.multiply(r).mod(n);
//         Point point = add(fastMultiply(u1),fastMultiplyWithPoint(u2,publicKeyPoint));
//         System.out.println(publicKeyPoint);
//         System.out.println(point);
//         if(r.equals(point.getX().mod(n))){
//             System.out.println("Verifyed");
//         }else {
//             System.out.println("error!");
//         }
//     }


//     public Point fastMultiply(BigInteger d){
//         Point point = G;
//         String dIn = d.toString(2);
//         for (int i = 1; i < dIn.length(); i++) {
//             int bit = Integer.parseInt(dIn.substring(i,i+1));
//             point = times2(point);
//             if (bit==1){point = add(point,G);}
//         }
//         return point;
//     }

//     /**
//      * point add method 点加法
//      * @param pointG
//      * @param pointQ
//      * @return
//      */
//     // public Point add(Point pointG,Point pointQ){
//     //     Point returnPoint = null;
//     //     if(pointG.equals(pointQ)){returnPoint = times2(pointG);}
//     //     else if (pointG.equals(Point.POINT_AT_INFINITY)){returnPoint = pointQ;}
//     //     else if (pointQ.equals(Point.POINT_AT_INFINITY)){returnPoint = pointG;}
//     //     else if (isInverse(pointG,pointQ)){returnPoint = Point.POINT_AT_INFINITY;}
//     //     else {
//     //         BigInteger s = pointQ.getY().subtract(pointG.getY()).mod(p).multiply((pointQ.getX().subtract(pointG.getX())).modInverse(p));
//     //         BigInteger pointX = s.multiply(s).subtract(pointG.getX()).subtract(pointQ.getX()).mod(p);
//     //         BigInteger pointY = (s.multiply(pointG.getX().subtract(pointX))).subtract(pointG.getY()).mod(p);
//     //         returnPoint = new Point(pointX,pointY);
//     //     }
//     //     return  returnPoint;
//     // }

//     /**
//      * point double method 点乘法
//      * @param pointG
//      * @return
//      */
//     public Point times2(Point pointG){
//         Point returnPoint = null;
//         if(pointG.equals(Point.POINT_AT_INFINITY)){ returnPoint = pointG;}else {
//             BigInteger s = (THREE.multiply(pointG.getX().modPow(TWO,p)).add(a)).mod(p).multiply(TWO.multiply(pointG.getY()).modInverse(p));
//             BigInteger pointX = s.multiply(s).subtract(pointG.getX()).subtract(pointG.getX()).mod(p);
//             BigInteger pointY = (s.multiply(pointG.getX().subtract(pointX))).subtract(pointG.getY()).mod(p);
//             returnPoint = new Point(pointX,pointY);
//         }

//         return returnPoint;
//     }

//     public boolean isInverse(Point pointG,Point pointT){
//         return (p.compareTo(pointT.getY().add(pointG.getY())) == 0 && pointG.getX().compareTo(pointT.getX()) == 0);
//     }

//     /**
//      * 判断坐标点是否在椭圆曲线上
//      * @param point
//      * @return
//      */
//     public boolean inPointOnCurve(Point point){
//         return point.getY().multiply(point.getY()).mod(p).equals((point.getX().multiply(point.getX()).multiply(point.getX())).add((a.multiply(point.getX()))).add(b).mod(p));
//     }

//     public Point fastMultiplyWithPoint(BigInteger d,Point pointG){
//         Point point = new Point(pointG.getX(),pointG.getY());
//         String dIn = d.toString(2);
//         for (int i = 1; i < dIn.length(); i++) {
//             int bit = Integer.parseInt(dIn.substring(i,i+1));
//             point = times2(point);
//             if (bit==1){point = add(point,pointG);}
//         }
//         return point;
//     }

}
