package com.vhklabs.ecdsa.utils;

import java.math.BigInteger;

/**
 * 以太坊协议构建工具包
 */
public class EthereumUtil {
    /**
     * 返回函数hash
     *
     * @param func
     * @return
     */
    public static String funcHash(String func) {
        return byte4(HashUtil.keccak256String(func));
    }

    /**
     * 获取data数据的前4 byte
     *
     * @param data
     * @return
     */
    public static String byte4(String data) {
        return data.substring(0, 8);
    }

    /**
     * 整数byte 32格式
     * @param number
     * @return
     */
    public static String number2Byte32(BigInteger number) {
        String hex = number.toString(16);
        for (int i = hex.length(); i < 64; i++) {
            hex = "0" + hex;
        }
        return hex;
    }

    /**
     * 地址byte 32格式
     * @param address
     * @return
     */
    public static String address2Byte32(String address) {
        address = address.replaceAll("0x","");
        for (int i = address.length(); i < 64; i++) {
            address = "0" + address;
        }
        return address;
    }

    /**
     * 数据byte 32格式
     * @param hex
     * @return
     */
    public static String hex2Byte32(String hex){
        for (int i = hex.length(); i < 64; i++) {
            hex = hex + "0";
        }
        return hex;
    }
}
