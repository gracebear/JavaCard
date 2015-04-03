package WalletDemoApplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class WalletDemoApplet extends Applet {
	
    private final static byte Wallet_CLA =(byte)0x80; 
    final static byte VERIFY = (byte) 0x20;
    private final static byte CREDIT = (byte) 0x30;
    private final static byte CONSUME = (byte) 0x40;
    private final static byte GET_BALANCE = (byte) 0x50;
    private final static byte GET_INTEGRAL =(byte)0x70;    
    private final static byte GET_CARDID= (byte) 0x01;
     
    //private final static byte GET_KEY =(byte)0x02; 
    
    //private final static  byte MAX_NUM_KEYS = 16;
    private final static  byte MAX_NUM_CARDID =8;
    // maximum balance
    private final static short MAX_BALANCE = (short)0x7fff;
    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    // signal the the INTEGRAL becomes negative
    final static short SW_EXCEED_MAXIMUM_INTEGRAL = 0x6A83;
    
    final static short SW_EXTERAL_MARK = 0x6A86;

    
    private final static byte tempmux[] = {(byte)0xff,(byte)0xff };
    private final static byte balance_new[] = {0x00,0x00};
    private final static byte tempmux1[] = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff };
    private final static byte balance_new1[] = {0x00,0x00,0x00,0x00};  
    private final static byte MaxIntegral[] = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff };
    private final static byte Integral_new[] = {0x00,0x00,0x00,0x00};  
	  short balance;
	  short integral;
	//private  byte  cardid[];
	//private  byte  key[];

	//private static final byte key[]    = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	//private static final byte cardid[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    final static byte PIN_TRY_LIMIT =(byte)0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE =(byte)0x08;
    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED =0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED =0x6301;
    
    boolean bRand,ExternalMark,verifyMark;
    
    OwnerPIN pin;
	DESKey Key;
	Cipher cipherDES_ECB_NOPAD;
	RandomData myRandomS;

	final static byte[] seed = {(byte)0x58, (byte)0x49, (byte)0x72, (byte)0x15, (byte)0x3E, (byte)0xA7, (byte)0xB0, (byte)0xC8};
	byte[] cardID;
	
	final static byte[] input = {(byte)0xC8, (byte)0xA2, 0x35, (byte)0x5E, 0x0F, 0x1B, (byte)0x86, (byte)0xE2};
	//= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	final static byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	byte[] output;
	short test=(short)0xfffe;
    private WalletDemoApplet(byte bArray[], short bOffset, byte bLength)
    {
       /* cardid=new byte[MAX_NUM_CARDID];
    	key  =new byte[MAX_NUM_KEYS];
        for (byte i = 0; i < MAX_NUM_KEYS; i++)
        	key[i] =i;
        for (byte i = 0; i < MAX_NUM_CARDID; i++)
        	cardid[i] =i;*/
 
    	balance  = 0;
    	integral = 0;
    	
    	
    	Key = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);    		
        //cipherDES_ECB_NOPAD = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
    	cipherDES_ECB_NOPAD = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M1, false);
		myRandomS = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        pin = new OwnerPIN(PIN_TRY_LIMIT,   MAX_PIN_SIZE);
        cardID = new byte[10];
        output = new byte[16];
        //input = new byte[16];
        bRand = false;
        ExternalMark=false;
        verifyMark=false;
        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset+iLen+1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset+cLen+1);
        byte aLen = bArray[bOffset]; // applet data length
        bOffset = (short)(bOffset+1);        
        byte pinLen = bArray[bOffset];
        
        
        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short)(bOffset+1), pinLen);
        
        // Initialize key
        bOffset = (short)(bOffset+pinLen+1);
        byte keyLen = bArray[bOffset];
        Key.setKey(bArray, (short)(bOffset+1));
        
        // Initialize cardID
        bOffset = (short)(bOffset+keyLen+1);
        byte idLen = bArray[bOffset];
        Util.arrayCopy(bArray, (short)(bOffset+1), cardID, (short)0, (short)idLen); 
        
        register();	
    }
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new WalletDemoApplet(bArray, bOffset, bLength);
		
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		byte[] buf = apdu.getBuffer();
		
		if ((buf[ISO7816.OFFSET_CLA] == Wallet_CLA) ||
	        (buf[ISO7816.OFFSET_CLA] == ISO7816.CLA_ISO7816))
		{
		    switch (buf[ISO7816.OFFSET_INS]) 
		    {
	        	case CREDIT:
	        		//credit(apdu);
	        		credit_extend(apdu);
	        		return;  
	        	case VERIFY  :
	        		verify(apdu);
	        		return;	        		
	        	case CONSUME :
	        		//consume(apdu);
	        		consume_extend(apdu);
	        		return;
	        	case GET_BALANCE:
	        		//getBalance(apdu);
	        		getBalance1(apdu);
	        		return;	        		
	        	case GET_INTEGRAL:
	        		getintegal(apdu);	        		
	        		return;
	        	case GET_CARDID: 
	        	    getcardid(apdu);
	        	    return;
	    		case (byte) 0x84:
	    			if(buf[ISO7816.OFFSET_CLA] != (byte)0x00)
	    			{
	    				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	    			}
	    		
	    			if(buf[ISO7816.OFFSET_P1] != (byte)0x00 || buf[ISO7816.OFFSET_P2] != (byte)0x00)
	    			{
	    				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	    			}
	    		
	    			if(buf[ISO7816.OFFSET_LC] > (byte)0x08)
	    			{
	    				ISOException.throwIt(Util.makeShort((byte)0x6C, (byte)0x08));
	    			}
	    			
	    			short responseLength = Util.makeShort((byte)0x00, (byte)buf[ISO7816.OFFSET_LC]);
	    		
	    			// Secure Random	    			
	    			myRandomS.setSeed(seed, (short)0, (short)0x08);
	    			myRandomS.generateData(buf, (short)ISO7816.OFFSET_CDATA, responseLength);
	    			/*buf[5]=11;
                    buf[6]=11;
                    buf[7]=11;
                    buf[8]=11;
                    buf[9]=11;
                    buf[10]=11;
                    buf[11]=11;
                    buf[12]=11; */	    			
	    			Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, input, (short)0, responseLength);
	    			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, responseLength);
	    			bRand = true;
	    			
	    			//short ouLen1 = calculateCryptogram(Key, input, (short)0, (short)8, output, (short)0);
	    			//byte[] output2={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	    			//ouLen1 = calculateCryptogram2(Key, output, (short)0, (short)8, output2, (short)0);
	    			break;
	    			
	    		case (byte) 0x82: // External Auth
	    		{
	    			if(bRand == false)
	    			{
	    				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    			}
	    			bRand = false;
	    			
	    			if(buf[ISO7816.OFFSET_LC] != (byte)0x08)
	    			{
	    				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    			}
	    			apdu.setIncomingAndReceive();
	    			short ouLen = calculateCryptogram(Key, input, (short)0, (short)8, output, (short)0);
	    			if(Util.arrayCompare(buf, (short)ISO7816.OFFSET_CDATA, output, (short)0, (short)8) != 0)
	    			{
	    				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	    			}
	    			ExternalMark=true;
	    			break;
	    		}

	    		case (byte) 0x88: // Internal Auth
	    		{
	    			bRand = false;

	    			if(buf[ISO7816.OFFSET_LC] != (byte)0x08)
	    			{
	    				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    			}
	    			
	    			apdu.setIncomingAndReceive();
	    			
	    			short ouLen = calculateCryptogram(Key, buf, (short)ISO7816.OFFSET_CDATA, (short)8, buf, (short)ISO7816.OFFSET_CDATA);
	    			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, ouLen);
	    			break;
	    		}	    		
		    	default:
		    		bRand = false;
		    		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		    }
		}
		else
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
	
	private short calculateCryptogram(DESKey key, byte[] input, short sin, short inLen, byte[] output, short sou)
	{
		short ouLen;
		
		//cipherDES_ECB_NOPAD.init(key, Cipher.MODE_ENCRYPT);
		cipherDES_ECB_NOPAD.init(key, Cipher.MODE_ENCRYPT, iv, (short)0, (short)8);
        ouLen = cipherDES_ECB_NOPAD.doFinal(input, (short)sin, (short)inLen, output, (short)sou);
		return ouLen;
	}
	private short calculateCryptogram2(DESKey key, byte[] input, short sin, short inLen, byte[] output, short sou)
	{
		short ouLen;
		
		//cipherDES_ECB_NOPAD.init(key, Cipher.MODE_ENCRYPT);
		cipherDES_ECB_NOPAD.init(key, Cipher.MODE_DECRYPT, iv, (short)0, (short)8);
        ouLen = cipherDES_ECB_NOPAD.doFinal(input, (short)sin, (short)inLen, output, (short)sou);
		return ouLen;
	}   
    private void credit(APDU apdu) {
        
        // access authentication
        if(!ExternalMark)
        	ISOException.throwIt(SW_EXTERAL_MARK);
        if ( ! pin.isValidated() )
            ISOException.throwIt    (SW_PIN_VERIFICATION_REQUIRED);
              
        byte[] buffer = apdu.getBuffer();

        short numBytes = (short)(buffer[ISO7816.OFFSET_LC]&0xFF);
        short byteRead =(short)(apdu.setIncomingAndReceive());
        
        if ( numBytes != byteRead)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // get the credit amount
        short creditAmount=0;
        if (numBytes==1)
            creditAmount= Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_CDATA]);
        else
        	creditAmount=Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if  (creditAmount==0 || (short)(balance + creditAmount)> MAX_BALANCE)
        	ISOException.throwIt(SW_NEGATIVE_BALANCE);

        balance = (short)(balance + creditAmount);

    } // end of deposit method
    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead =(byte)(apdu.setIncomingAndReceive());

      // check pin
        // the PIN data is read into the APDU buffer
      // at the offset ISO7816.OFFSET_CDATA
      // the PIN data length = byteRead
      if ( pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead) == false )
         ISOException.throwIt(SW_VERIFICATION_FAILED);
      //verifyMark=true;
    }
    private void consume(APDU apdu) {
    
        /*if ( ! verifyMark )
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);*/
        if ( ! pin.isValidated() )
            ISOException.throwIt    (SW_PIN_VERIFICATION_REQUIRED);
        byte[] buffer = apdu.getBuffer();
        
        short numBytes = (short)buffer[ISO7816.OFFSET_LC];
        
        short byteRead =(short)(apdu.setIncomingAndReceive());
        
        if ( numBytes != byteRead)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // get the balance amount
        short debitAmount=0;
        if (numBytes==1)
        	debitAmount= Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_CDATA]);
        else
        	debitAmount=Util.getShort(buffer, ISO7816.OFFSET_CDATA);

        if (debitAmount==0 || debitAmount>balance)
        	ISOException.throwIt(SW_NEGATIVE_BALANCE);
          	
        //integral= (short)(integral + debitAmount/100);
        calIntegral(buffer, ISO7816.OFFSET_CDATA,numBytes);
        balance = (short)(balance - debitAmount);
    
    } // end of debit method
    
    private void getBalance(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();        
        short le = apdu.setOutgoing();
        apdu.setOutgoingLength((byte)2);
        
        buffer[0] = (byte)(balance >> 8);
        buffer[1] = (byte)(balance & 0xFF);
        
        apdu.sendBytes((short)0, (short)2);
    
    }  
    private void getBalance1(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();  
        short le = apdu.setOutgoing();	        
        apdu.setOutgoingLength((byte)2);   
        apdu.sendBytesLong(balance_new, (short)0, (short)2);
    
    } 
    private void getintegal(APDU apdu) 
    {
    	/*byte[] buffer = apdu.getBuffer();      
        Util.setShort(buffer,(short)0,(short)integral);
    	apdu.setOutgoingAndSend((short) 0, (short) 2);*/
        byte[] buffer = apdu.getBuffer();  
        short le = apdu.setOutgoing();	        
        apdu.setOutgoingLength((byte)4);   
        apdu.sendBytesLong(Integral_new, (short)0, (short)4);
    }
    private void getcardid(APDU apdu)
    {
        short le = apdu.setOutgoing();
        apdu.setOutgoingLength(MAX_NUM_CARDID);
        apdu.sendBytesLong(cardID,(short)0, (short)8);
    }
    private void credit_extend(APDU apdu) {
        
	    // access authentication
    	
        if(!ExternalMark)
        	ISOException.throwIt(SW_EXTERAL_MARK);
        if ( ! pin.isValidated() )
            ISOException.throwIt    (SW_PIN_VERIFICATION_REQUIRED);	    
	    byte[] buffer = apdu.getBuffer();
	
	    short numBytes = (short)buffer[ISO7816.OFFSET_LC];
	    short byteRead =(short)(apdu.setIncomingAndReceive());
	    
	    if ( numBytes != byteRead)
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    
	    // get the credit amount
	    short low=0,high=0;
	    byte temp[]={0x00,0x00};
	    if ((short)(buffer[ISO7816.OFFSET_CDATA]& 0xff)==0 && (short)(buffer[ISO7816.OFFSET_CDATA+1]& 0xff)==0) //consume amount is 0
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);//credit amount is 0
    
        Util.arrayCopy(balance_new,(short)(0),temp,(short)0,(short)2);  

	    
	    low=(short)(buffer[ISO7816.OFFSET_CDATA+1]& 0xff);
	    low=(short)(low+(temp[1]&0xff));
        byte aa = (byte)(low >> 8);
        temp[1] = (byte)(low & 0xFF);
        
        high=(short)(buffer[ISO7816.OFFSET_CDATA]& 0xff);
        high=(short)(high+aa+(temp[0]&0xff));
        aa = (byte)(high >> 8);
        temp[0] = (byte)(high & 0xFF); 
        
        if(aa>0)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if((short)(tempmux[0]&0xff)< (short)(temp[0]&0xff))
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
    	Util.arrayCopy(temp,(short)0,balance_new,(short)0,(short)2);

        	
    } // end of deposit method
    private void consume_extend(APDU apdu) {        
        if ( ! pin.isValidated() )
            ISOException.throwIt    (SW_PIN_VERIFICATION_REQUIRED);
	    byte[] buffer = apdu.getBuffer();
	
	    short numBytes = (short)buffer[ISO7816.OFFSET_LC];
	    short byteRead =(short)(apdu.setIncomingAndReceive());
	    
	    if ( numBytes != byteRead )
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    
	    // get the consume amount	
	    byte temp[]={0x00,0x00};
	    Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA),temp,(short)0,(short)2);
	    //short result=(short)(Util.getShort(buffer, ISO7816.OFFSET_CDATA));//避免ffff情况
	    if ((short)(temp[0]& 0xff)==0 && (short)(temp[1]& 0xff)==0) //consume amount is 0
	    	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    if((short)(balance_new[0]&0xff)< (short)(temp[0]& 0xff)) 
	    	ISOException.throwIt(SW_NEGATIVE_BALANCE);
	    if ((short)(balance_new[0]&0xff)==(short)(temp[0]& 0xff) &&  ((short)(balance_new[1]&0xff)< (short)(temp[1]& 0xff)))
	    		ISOException.throwIt(SW_NEGATIVE_BALANCE);
	    short low=0,high=0;	    
        Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA),temp,(short)0,(short)2);
        calIntegral(buffer, ISO7816.OFFSET_CDATA,numBytes);
        
	    low=(short)(balance_new[1]& 0xff);
	    high=(short)(balance_new[0]& 0xff);
	    if (low<(short)(temp[1]&0xff))
	    {
	    	high=(short)(high-1);
	    	low=(short)(low+0x0100-temp[1]&0xff);
	    	temp[1]=(byte)(low & 0xff);	    	
	    }
	    else
	    {
	    	low=(short)(low-temp[1]&0xff);
	    	temp[1]=(byte)(low & 0xff);	    	
	    }
	    
	    high=(short)(high-temp[0]);
        temp[0] = (byte)(high & 0xFF);
        Util.arrayCopy(temp,(short)(0),balance_new,(short)0,(short)2);       

    } // end of depos	
    private void credit_extend2(APDU apdu) {
        
	    // access authentication
        if(!ExternalMark)
        	ISOException.throwIt(SW_EXTERAL_MARK);
        if ( ! pin.isValidated() )
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);    
	    byte[] buffer = apdu.getBuffer();
	
	    short numBytes = buffer[ISO7816.OFFSET_LC];
	    short byteRead =apdu.setIncomingAndReceive();
	    
	    if ( numBytes != byteRead)
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    
	    // get the credit amount
	    short low=0;
	    byte temp[]={0x00,0x00,0x00,0x00};
	    //short i= (short)(ISO7816.OFFSET_CDATA+numBytes); //numBytes+ISO7816.OFFSET_CDATA;
	    Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA),temp,(short)0,numBytes );
	    //short result=(short)(Util.getShort(buffer, ISO7816.OFFSET_CDATA));//避免ffff情况
        if((short)(temp[0]& 0xff)==0 && (short)(temp[1]& 0xff)==0 && (short)(temp[2]& 0xff)==0 && (short)(temp[3]& 0xff)==0)
	    	    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//credit amount is 0
        Util.arrayFillNonAtomic(temp, (short)0,(short)numBytes,(byte)0);
        Util.arrayCopy(balance_new1,(short)(0),temp,(short)0,numBytes);  
        short j=3;
        byte aa=0;
        for(short i= (short)(ISO7816.OFFSET_CDATA+numBytes-1);i>=(short)(ISO7816.OFFSET_CDATA);i--)
        {
		    low=(short)(buffer[i]& 0xff);
		    low=(short)(low+aa+(temp[j]&0xff));
	        aa = (byte)(low >> 8);
	        temp[j] = (byte)(low & 0xFF);
	        j--;	        	
        }
 
        if(aa>0)
        	ISOException.throwIt(SW_NEGATIVE_BALANCE);

        if((short)(tempmux1[0]&0xff)<(short)(temp[0]&0xff))	        
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
        else if((short)(tempmux1[0]&0xff)==(short)(temp[0]&0xff))
        {
 	        if((short)(tempmux1[1]&0xff)<(short)(temp[1]&0xff))
 	        	ISOException.throwIt(SW_NEGATIVE_BALANCE);
 	        else if((short)(tempmux1[1]&0xff)==(short)(temp[1]&0xff))
 	        {
	 	        if((short)(tempmux1[2]&0xff)<(short)(temp[2]&0xff))
	 	        	ISOException.throwIt(SW_NEGATIVE_BALANCE); 
	 	        else if ((short)(tempmux1[2]&0xff)==(short)(temp[2]&0xff))
	 	        {
	 	        	if((short)(tempmux1[3]&0xff)<(short)(temp[3]&0xff))
		 	        	ISOException.throwIt(SW_NEGATIVE_BALANCE); 	
	 	        }		 	        	
 	        }
        }      
    	Util.arrayCopy(temp,(short)0,balance_new1,(short)0,(short)numBytes);

        	
    } // end of deposit method
    private void consume_extend2(APDU apdu) {        
        if ( ! pin.isValidated() )
            ISOException.throwIt    (SW_PIN_VERIFICATION_REQUIRED);
        
	    byte[] buffer = apdu.getBuffer();
	
	    short numBytes = (short)buffer[ISO7816.OFFSET_LC];
	    short byteRead =(short)(apdu.setIncomingAndReceive());
	    
	    if ( numBytes != byteRead )
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    
	    // get the consume amount	
	    byte temp[]={0x00,0x00,0x00,0x00};
	    Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA),temp,(short)0,numBytes );
	    //short result=(short)(Util.getShort(buffer, ISO7816.OFFSET_CDATA));//避免ffff情况
        if((short)(temp[0]& 0xff)==0 && (short)(temp[1]& 0xff)==0 && (short)(temp[2]& 0xff)==0 && (short)(temp[3]& 0xff)==0)
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if((short)(balance_new1[0]&0xff)<(short)(temp[0]&0xff))	        
        	ISOException.throwIt(SW_NEGATIVE_BALANCE);	
        else if((short)(balance_new1[0]&0xff)==(short)(temp[0]&0xff))
        {
 	        if((short)(balance_new1[1]&0xff)<(short)(temp[1]&0xff))
 	        	ISOException.throwIt(SW_NEGATIVE_BALANCE);
 	        else if((short)(balance_new1[1]&0xff)==(short)(temp[1]&0xff))
 	        {
	 	        if((short)(balance_new1[2]&0xff)<(short)(temp[2]&0xff))
	 	        	ISOException.throwIt(SW_NEGATIVE_BALANCE); 
	 	        else if ((short)(balance_new1[2]&0xff)==(short)(temp[2]&0xff))
	 	        {
	 	        	if((short)(balance_new1[3]&0xff)<(short)(temp[3]&0xff))
		 	        	ISOException.throwIt(SW_NEGATIVE_BALANCE); 	
	 	        }		 	        	
 	        }
        }
        calIntegral(buffer, ISO7816.OFFSET_CDATA,numBytes);	    		    
        Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA),temp,(short)0,(short)2);
        short low=0;
        byte aa=0;
        for(short j=3 ;j>=0; j--)
        {
        	low=(short)(balance_new1[j]& 0xff-aa);
		    if (low<(short)(temp[j]&0xff))
		    {
		    	aa=1;
		    	low=(short)(low+0x0100-temp[j]&0xff);
		    	temp[j]=(byte)(low & 0xff);	    	
		    }
		    else
		    {   
		    	aa=0;
		    	low=(short)(low-temp[j]&0xff);
		    	temp[j]=(byte)(low & 0xff);	    	
		    }
       } 
        Util.arrayCopy(temp,(short)(0),balance_new1,(short)0,(short)numBytes);       

    } // end of depos	
    private void getBalance2(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();  
        short le = apdu.setOutgoing();	        
        apdu.setOutgoingLength((byte)4);   
        apdu.sendBytesLong(balance_new1, (short)0, (short)4);
    
    } 
    private void calIntegral(byte [] buf,byte soff,short len)
    {
    	byte temp[]={0x00,0x00,0x00,0x00};
    	short low=0;
    	byte aa=0;
        if (len==2)
  	        Util.arrayCopy(buf, soff, temp,(short)2, len);
        else
        	Util.arrayCopy(buf, soff, temp,(short)0, len);
        for(short i= 3;i>=0;i--)
        {
		    low=(short)(Integral_new[i]& 0xff);
		    low=(short)(low+aa+(temp[i]&0xff));
	        aa = (byte)(low >> 8);
	        temp[i] = (byte)(low & 0xFF);       	
        }
        if(aa>0)
        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL);

        if((short)(MaxIntegral[0]&0xff)<(short)(temp[0]&0xff))	        
        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL);	
        else if((short)(MaxIntegral[0]&0xff)==(short)(temp[0]&0xff))
        {
 	        if((short)(MaxIntegral[1]&0xff)<(short)(temp[1]&0xff))
 	        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL);
 	        else if((short)(MaxIntegral[1]&0xff)==(short)(temp[1]&0xff))
 	        {
	 	        if((short)(MaxIntegral[2]&0xff)<(short)(temp[2]&0xff))
	 	        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL); 
	 	        else if ((short)(MaxIntegral[2]&0xff)==(short)(temp[2]&0xff))
	 	        {
	 	        	if((short)(MaxIntegral[3]&0xff)<(short)(temp[3]&0xff))
		 	        	ISOException.throwIt(SW_EXCEED_MAXIMUM_INTEGRAL); 	
	 	        }		 	        	
 	        }
        }      
    	Util.arrayCopy(temp,(short)0,Integral_new,(short)0,(short)4);
    }
  }
