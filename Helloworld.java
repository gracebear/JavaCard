/* 
 * This should be the first applet to study javacard applet development.
 * This applet was tested on JCIDE(http://www.javacos.com/sdkinfo.php). 
 * @ author: gracebear
 * Make a Little Progress Every Day
 * 
 */


package helloworld;

import javacard.framework.*;

public class helloworld extends Applet 
{
    private byte[] Bytes_Buffer;
    private static final short LENGTH_BYTES = 256;
    
    protected helloworld() 
    {
        Bytes_Buffer = new byte[LENGTH_BYTES];
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) 
    {
        new helloworld();
    }

    public void process(APDU apdu) 
    {
        byte buffer[] = apdu.getBuffer();
        short Bytes_Read = apdu.setIncomingAndReceive();
        short Offset = (short) 0;

        while (Bytes_Read > 0) 
        {                                 
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, Bytes_Buffer, Offset, Bytes_Read);
            Offset += Bytes_Read;
            Bytes_Read = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (Offset + 5));
        apdu.sendBytes((short) 0, (short) 5);
        apdu.sendBytesLong(Bytes_Buffer, (short) 0, Offset);
    }

}
