/**
 * @author Vitor Arins
 */

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ProjetoaesModoCBC {
    
    private final int IV_LENGTH = 16;
    private SecretKeySpec secretKey;
    private IvParameterSpec ivSpec;
    private Cipher cipher;
   
   public void inicia() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException{

       // Incluido: Instanciar um novo Security provider
//       int addProvider = Security.addProvider(new BouncyCastleProvider());

       // Instancia o cipher
//       cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
       cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

       // Chave na String
       byte[] key = {};
       String chave1 = "43b23e8c67e7967eeb8ac5c08d5abbf8";
//       String chave1 = "3efc333d75c6192078bbd869d563a825";

       try {
           key = Hex.decodeHex(chave1.toCharArray());
       } catch (DecoderException ex) {
           System.out.println(ex);
       }
       secretKey = new SecretKeySpec(key, "AES");
       System.out.println("Chave AES = " + Hex.encodeHexString(secretKey.getEncoded()));

       byte iv[] = new byte[16];

       String iv1 = "b60eac7b83dc8ac1b3e0d0531a7b11ac";
       try {
           iv = Hex.decodeHex(iv1.toCharArray());
       }
       catch (DecoderException ex) {
           System.out.println(ex);
       }

       ivSpec = new IvParameterSpec(iv);

   } // fim inicia
    
    public String encrypt(String strToEncrypt) {
        try {            
            try {
                inicia();
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(ProjetoaesModoCBC.class.getName()).log(Level.SEVERE, null, ex);
            }
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            final String encryptedString = Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
            return encryptedString;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
        }
        return null;

    }

    public String decrypt(String dec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {

            try {
                inicia();
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(ProjetoaesModoCBC.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
            byte[] embytes = {};
            try {
                embytes = Hex.decodeHex(dec.toCharArray());
            } catch (DecoderException ex) {
                Logger.getLogger(ProjetoaesModoCBC.class.getName()).log(Level.SEVERE, null, ex);
            }

            byte[] buf = new byte[cipher.getOutputSize(embytes.length)];

            int bufLength = cipher.update(embytes, 0, embytes.length, buf, 0);

            bufLength += cipher.doFinal(buf, bufLength);

            // remove the iv from the start of the message
            byte[] plainText = new byte[bufLength - IV_LENGTH];

            System.arraycopy(buf, IV_LENGTH, plainText, 0, plainText.length);

            String decryptedString = new String(plainText);
//            String decryptedString = Utils.toHex(plainText, plainText.length);

            return decryptedString;

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        } catch (ShortBufferException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String args[]) throws InvalidKeyException, InvalidAlgorithmParameterException {
        ProjetoaesModoCBC obj = new ProjetoaesModoCBC();

        String cifrada = "c72694c2b2eb48531d1d06c2909a3bad326fdff77f429abe6e88204fdbf5288159074444e5c" +
                "e92468e45073c0a80da742181a425eb27c942b3e29f2d40f023c3";

//        String cifrada = "4c014a87e3bcfd32ae2c29398c08945745ca8a4c6b911f323cf53937e5fce74be43d5098d0ab110d395ce85452c01b7c";
        System.out.println("Mensagem cifrada = " + cifrada );
        String decifrada = obj.decrypt(cifrada);
        System.out.println("Mensagem decifrada = " + decifrada);
    }
}
