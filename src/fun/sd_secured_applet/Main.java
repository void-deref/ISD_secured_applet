package fun.sd_secured_applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

public class
Main extends Applet
{   
    private final static byte CLA_PROPRIETARY   = (byte)0x80;
    private final static byte INS_SET_SECRET    = (byte)0x20;
    private final static byte INS_GET_SECRET    = (byte)0x22;
    private final static byte INS_INIT_UPDATE   = (byte)0x50;

    // Mask the secure messaging bit 3 of the Class byte
    private final static byte SM_MASK = (byte)0xFB;

    private final static short _00 = 0x00;
    private final static short _64 = 0x40;

    private SecureChannel scp02;
    private byte[] secret;
    private short secret_len;

    public
    Main()
    {
        secret = new byte[_64];
        secret_len = _00;
    }

    public static void
	install(byte[] buffer, short offset, byte length)
	{
		Main applet = new Main();

        length  = buffer[offset++];    // instance AID length
        // offset += length;           // jump over to AID field
        // offset++;                   // privileges length
        // offset++;                   // privileges byte
        // length  = buffer[offset++]; // app specific params length

        applet.register(buffer, offset, length);
	}

    @Override
    public void
    process(APDU apdu) throws ISOException
    {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();     
        byte cla = (byte)(buffer[ISO7816.OFFSET_CLA] & SM_MASK);

        if(cla != CLA_PROPRIETARY) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_SET_SECRET: {
                set_secret(apdu);
            } break;
            case INS_GET_SECRET: {
                get_secret(apdu);
            } break;
            case INS_INIT_UPDATE:
            case ISO7816.INS_EXTERNAL_AUTHENTICATE:
                mutual_authentication(apdu);
            break;
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
    set_secret(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short apdu_len = apdu.setIncomingAndReceive();
        apdu_len = scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));
        apdu_len -= 5;
        secret_len = (short)((short)buffer[ISO7816.OFFSET_CDATA] & (short)0x00FF);
        Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + 1), secret, _00, apdu_len);
    }

    protected void
    get_secret(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short apdu_len = apdu.setIncomingAndReceive();
        scp02.unwrap(buffer, ISO7816.OFFSET_CLA, (short)(apdu_len + 5));

        Util.arrayCopyNonAtomic(secret, _00, buffer, ISO7816.OFFSET_CDATA, secret_len);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, secret_len);
        
    }

    /* SCPcommands method
    *  Method to handle the Secure Channel Protocol commands defined in the 
    *  GlobalPlatform specifications, such as: INITIALIZE UPDATE and EXTERNAL
    *  AUTHENTICATE commands. 
    *  The processing for these commands is performed by the Security Domain 
    *  associated with the application. 
    *  Errors are managed and output by the Security Domain.
    *  Parameters
    *       apdu :- the apdu buffer.
   **/ 
   protected void
   mutual_authentication(APDU apdu) {
    short resp_len = scp02.processSecurity(apdu);
    if (resp_len != 0 )
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, resp_len);
    }
}
