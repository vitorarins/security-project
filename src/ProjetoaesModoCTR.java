/**
 * @author Vitor Arins
 */

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ProjetoaesModoCTR {
    
    private final int IV_LENGTH = 16;
    private SecretKeySpec secretKey;
    private IvParameterSpec ivSpec;
    private Cipher cipher;
   
   public void inicia() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException{

       // Instancia o cipher
       cipher = Cipher.getInstance("AES/CTR/NoPadding");

       // Chave na String
       byte[] key = {};
       String chave1 = "7d616b5636c9596d1f940d994efada93";

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
                Logger.getLogger(ProjetoaesModoCTR.class.getName()).log(Level.SEVERE, null, ex);
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
                Logger.getLogger(ProjetoaesModoCTR.class.getName()).log(Level.SEVERE, null, ex);
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
                Logger.getLogger(ProjetoaesModoCTR.class.getName()).log(Level.SEVERE, null, ex);
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
        ProjetoaesModoCTR obj = new ProjetoaesModoCTR();

        String cifrada = "97fd649cf193f896ca0dcfd7d0edffbe8cbba27bfb1f3654618af62b3acad13a65514b1132910" +
                "38adae1dac10abe0920be4d77ea12633ab030eb73167412a6c00340d9ef2a08dda57e7765d" +
                "37b12f2ee9376d061aea90b31";

        System.out.println("Mensagem cifrada = " + cifrada );
        String decifrada = obj.decrypt(cifrada);
        System.out.println("Mensagem decifrada = " + decifrada);
    }
}
