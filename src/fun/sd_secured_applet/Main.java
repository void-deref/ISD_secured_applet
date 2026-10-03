package fun.sd_secured_applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import javacard.security.CryptoException;
import javacard.security.AESKey;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

public class
Main extends Applet
{   
    private static final short SW_ARRAY_INDEX_OUT_OF_RANGE = (short)0x6703;
	private static final short SW_CRYPTO_EXCEPTION         = (short)0x6600;

    private final static byte INS_SET_SECRET_KEY    = (byte)0x20;
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
    private short  person_info_len = 0;
    private byte[] person_info     = null;

    private AESKey aes_key         = null;
    private Cipher aes_cipher      = null;
    private SecureChannel scp02;
    
    public
    Main()
    {
        person_info = new byte[_255];
        // NOTE: allocating cryptography objects at instantiation stage leads to SW 6F00.
    }

    public static void
	install(byte[] buffer, short offset, byte length)
	{
		length = buffer[offset++]; // the the length of instance AID. The 'offset' will point to the first byte of AID
        new Main().register(buffer, offset, length);
	}

    @Override
    public void
    process(APDU apdu) throws ISOException
    {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();  
        byte ins      = buffer[ISO7816.OFFSET_INS];   
        short len     = _00;

        try {
            if (has_cdata(ins)) {
                len = apdu.setIncomingAndReceive();
                if (len != apdu.getIncomingLength()) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
            }
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_SET_SECRET_KEY: {
                    len = update_secret_key(buffer, len);
                } break;
                case INS_GET_PERSONAL_INFO: {
                    len = get_person_info(buffer, len);
                } break;
                case INS_SET_PERSONAL_INFO: {
                    len = set_person_info(buffer, len);
                } break;
                default:
                    len = mutual_authentication(apdu);
            }

            if (len > _00) {
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ARRAY_INDEX_OUT_OF_RANGE);
        } catch (CryptoException e) {
            short reason = (short)(e.getReason() & (short)0x00FF);
            ISOException.throwIt((short)(SW_CRYPTO_EXCEPTION | reason));
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


    protected short
    update_secret_key(byte[] buffer, short apdu_len)
    {
        apdu_len = scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));
        apdu_len -= 5;

        if (aes_key == null) {
            aes_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aes_cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        }
        aes_key.setKey(buffer, ISO7816.OFFSET_CDATA);

        return _00;
    }

    protected short
    set_person_info(byte[] buffer, short apdu_len)
    {
        person_info_len = scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));
        person_info_len -= 5;
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, person_info, _00, person_info_len);
        return _00;
    }

    protected short
    get_person_info(byte[] buffer, short apdu_len)
    {
        aes_cipher.init(aes_key, Cipher.MODE_ENCRYPT);
        short out_data_len = aes_cipher.doFinal(person_info, _00, person_info_len, buffer, ISO7816.OFFSET_CDATA);
        return out_data_len;
    }


    protected short
    mutual_authentication(APDU apdu)
    {
        short resp_len = scp02.processSecurity(apdu);
        return resp_len;
    }

    private boolean
    has_cdata(byte ins)
    {
        boolean result;
		
        switch (ins) {
            case INS_SET_SECRET_KEY:
			case INS_SET_PERSONAL_INFO:
                result = true;
            break;
            default: result = false;
        }
        return result;
    }
}
