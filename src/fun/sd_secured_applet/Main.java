package fun.sd_secured_applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.HMACKey;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

public class
Main extends Applet
{   
    private final static byte CLA_GLOBAL_PLATFORM = (byte)0x80;
    private final static byte INS_SET_SECRET_KEY  = (byte)0x20;
    private final static byte INS_GET_PERSONAL_INFO = (byte)0x22;
    private final static byte INS_SET_PERSONAL_INFO = (byte)0x24;

    // Mask the secure messaging bit 3 of the Class byte
    private final static byte SM_MASK = (byte)0xFB;

    private final static short _00 = 0x00;
    private final static short _01 = 0x01;
    private final static short _32 = 0x20;
    private final static short _64 = 0x40;
    private final static short _255 = 0xFF;

    /**
     * 11 xx [surname]
     * 12 xx [name]
     * 13 xx [middle/patronymic name]
     * 
     * 14 xx [department]
     * 15 xx [division]
     * 16 xx [position]
     */
    private byte[]        person_info;
    private short         person_info_len;
    private HMACKey       hmac_key = null;
    private SecureChannel scp02;
    
    public
    Main(byte[] buffer, short offset, byte length)
    {
        person_info = new byte[_255];
        
        // aes_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, true);
        // aes256_key.setKey(signature_key, _32);
        // aes_mac_256_no_pad = Signature.getInstance(Signature.ALG_AES_MAC_256_NOPAD, false);
    }

    public static void
	install(byte[] buffer, short offset, byte length)
	{
		Main applet;

        byte  aid_len = buffer[offset++];
        short aid_off = offset;
        // offset += aid_len;          // jump over to privileges field
        // offset++;                   // privileges length
        // offset++;                   // privileges byte
        // length  = buffer[offset++]; // app specific params length

        // if (length != _32) {
        //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH | _01));
        // }

        applet = new Main(buffer, offset, length);
        applet.register(buffer, aid_off, aid_len);
	}

    @Override
    public void
    process(APDU apdu) throws ISOException
    {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();     
        
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_SET_SECRET_KEY: {
                update_secret_key(apdu);
            } break;
            case INS_GET_PERSONAL_INFO: {
                get_person_info(apdu);
            } break;
            case INS_SET_PERSONAL_INFO: {
                set_person_info(apdu);
            } break;
            default:
                mutual_authentication(apdu);
        }

    }
    
    @Override
    public boolean
    select()
    {
        scp02 = GPSystem.getSecureChannel();
        return true;
    }

    @Override
    public void
    deselect()
    {
        scp02.resetSecurity();
    }


    protected void
    update_secret_key(APDU apdu)
    {
        byte[] buffer  = apdu.getBuffer();
        short apdu_len = apdu.setIncomingAndReceive();
        apdu_len = scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));

        // if (aes_key == null) {
        //     aes_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        //     aes_cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        // }
        // apdu_len -= 5;
        // signature_key_len = (short)((short)buffer[ISO7816.OFFSET_CDATA] & (short)0x00FF);
        // Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + 1), signature_key, _00, apdu_len);
    }

    protected void
    set_person_info(APDU apdu)
    {
        byte[] buffer  = apdu.getBuffer();
        short apdu_len = apdu.setIncomingAndReceive();
        
        person_info_len = scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));
        person_info_len -= 5;
        // person_info_len = (short)(buffer[ISO7816.OFFSET_LC] & 0x00FF);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, person_info, _00, person_info_len);
    }

    protected void
    get_person_info(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short apdu_len = apdu.setIncomingAndReceive();
        apdu_len = scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));
        apdu_len -= 5;

        Util.arrayCopyNonAtomic(person_info, _00, buffer, ISO7816.OFFSET_CDATA, person_info_len);
        short out_data_len = scp02.wrap(buffer, ISO7816.OFFSET_CLA, (short)(person_info_len + 2));
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, out_data_len);

        // Util.arrayCopyNonAtomic(signature_key, _00, buffer, ISO7816.OFFSET_CDATA, signature_key_len);

        // signature_key_len = scp02.wrap(buffer, ISO7816.OFFSET_CDATA, (short)(signature_key_len + 2));
        // apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signature_key_len);
    }
 
    protected void
    mutual_authentication(APDU apdu)
    {
        short resp_len = scp02.processSecurity(apdu);
        if (resp_len != 0 ) {
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, resp_len);
        }
    }
}
