package com.test.union.utils;

import java.security.Key;  
import java.security.KeyFactory;  
import java.security.KeyPair;  
import java.security.KeyPairGenerator;  
import java.security.PrivateKey;  
import java.security.PublicKey;  
import java.security.Signature;  
import java.security.interfaces.RSAPrivateKey;  
import java.security.interfaces.RSAPublicKey;  
import java.security.spec.PKCS8EncodedKeySpec;  
import java.security.spec.X509EncodedKeySpec;  
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
  
import javax.crypto.Cipher;  
  
import org.apache.commons.codec.binary.Base64;  

import com.google.common.collect.Ordering;
import com.pay.common.util.StringUtil;
  
import sun.misc.BASE64Decoder;  
import sun.misc.BASE64Encoder;  
   
   
public class RSAtest{  
    public static final String KEY_ALGORITHM="RSA";  
    public static final String SIGNATURE_ALGORITHM="MD5withRSA";  
      /** 
       * 得到公钥 
       * @param key 密钥字符串（经过base64编码） 
       * @throws Exception 
       */  
      public static PublicKey getPublicKey(String key) throws Exception {  
            byte[] keyBytes;  
            keyBytes = (new BASE64Decoder()).decodeBuffer(key);  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
            PublicKey publicKey = keyFactory.generatePublic(keySpec);  
            return publicKey;  
      }  
      /** 
       * 得到私钥 
       * @param key 密钥字符串（经过base64编码） 
       * @throws Exception 
       */  
      public static PrivateKey getPrivateKey(String key) throws Exception {  
            byte[] keyBytes;  
            keyBytes = (new BASE64Decoder()).decodeBuffer(key);  
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);  
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);  
            return privateKey;  
      }  
  
      //***************************签名和验证*******************************  
      public static byte[] sign(byte[] data,String str_priK) throws Exception{  
        PrivateKey priK = getPrivateKey(str_priK);  
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);       
        sig.initSign(priK);  
        sig.update(data);  
        return sig.sign();  
    }  
      
    public static boolean verify(byte[] data,byte[] sign,String str_pubK) throws Exception{  
        PublicKey pubK = getPublicKey(str_pubK);  
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);  
        sig.initVerify(pubK);  
        sig.update(data);  
        return sig.verify(sign);  
    }  
      
    //************************加密解密**************************  
    public static byte[] encrypt(byte[] bt_plaintext,String str_pubK)throws Exception{  
        PublicKey publicKey = getPublicKey(str_pubK);  
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
        byte[] bt_encrypted = cipher.doFinal(bt_plaintext);  
        return bt_encrypted;  
    }  
      
    public static byte[] decrypt(byte[] bt_encrypted，String str_priK)throws Exception{  
        PrivateKey privateKey = getPrivateKey(str_priK);  
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);  
        byte[] bt_original = cipher.doFinal(bt_encrypted);  
        return bt_original;  
    }  
    //*********************根据ASCII码排序(字典序)*********************
    public static String hex(Map<String,Object> map){
		String[] strs = new String[map.size()];
		map.keySet().toArray(strs);
		Arrays.sort(strs);
		StringBuffer source = new StringBuffer();
		for(String str:strs){
			source.append(str+"="+map.get(str)+"&");
		}
		String bigstr = source.substring(0,source.length()-1);
		return bigstr;
	}
    //********************main函数：加密解密和签名验证*********************  
      public static void main(String[] args) throws Exception {  
            String str_plaintext = "这是一段用来测试密钥转换的明文";  
            System.err.println("明文："+str_plaintext);  
            byte[] bt_cipher = encrypt(str_plaintext.getBytes());  
            System.out.println("加密后："+Base64.encodeBase64String(bt_cipher));  
              
            byte[] bt_original = decrypt(bt_cipher);  
            String str_original = new String(bt_original);  
            System.out.println("解密结果:"+str_original); 
              
            String str="被签名的内容";  
            System.err.println("\n原文:"+str);  
            byte[] signature=sign(str.getBytes());  
            System.out.println("产生签名："+Base64.encodeBase64String(signature));  
            boolean status=verify(str.getBytes(), signature);  
            System.out.println("验证情况："+status);  
      }  
   
}  