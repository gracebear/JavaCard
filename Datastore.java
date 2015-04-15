/*
 * This is a simple applet for the absolute beginners of javacard applet development.
 * This applet was tested on JCIDE(http://www.javacos.com/developmentkit.php). 
 * @ author: gracebear
 * Make a Little Progress Every Day
 */
package com.ftsafe.javacard.datastore;
 
import javacard.framework.*;
 
public class Datastore extends Applet
{
 
	final static byte CLA =(byte)0x80;
	final static byte INS_CREATE=(byte)0X01;
	final static byte INS_READ_DATA=(byte)0x02;
	final static byte INS_WRITE_DATA=(byte)0x03;
	final static byte INS_RELEASE=(byte)0X04;
	
	final static short SW_COMMAND_ERROR=0x6F01;
	final static short SW_CREATE_REQUIRED=0x6F02;
	final static short SW_DUPLICATE_CREATE=0x6F03;
	final static short SW_READING_OUTOF_BOUNDS=0x6F04;
	final static short SW_WRITING_OUTOF_BOUNDS=0X6F05;
	final static short SW_PIN_VERIFICATION_REQUIRED=0x6F06;
 
	private  byte[] DataBuffer;
	short byteLength;
	short Data;
		
	public Datastore()
	{
		
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new Datastore().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	public boolean select()
	{
		return true;
	}
 
	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}
		byte[] buffer = apdu.getBuffer();
		
		if(buffer[ISO7816.OFFSET_CLA]!=CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(apdu.isISOInterindustryCLA())
		{
			if(buffer[ISO7816.OFFSET_INS]==(byte)(0XA4))
			{
				return;
			}
			else
			{
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			}
		}
		
		short p1p2=Util.getShort(buffer,ISO7816.OFFSET_P1);
		
		switch (buffer[ISO7816.OFFSET_INS])
		{
		case INS_CREATE:
			if(p1p2!=0)
			{
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}
			create(apdu);
			return;
		case INS_READ_DATA:
			readData(apdu);
			return;
		case INS_WRITE_DATA:
			writeData(apdu);
			return;
		case INS_RELEASE:
			release(apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void create(APDU apdu)
	{
		if(DataBuffer!=null)
		{
			ISOException.throwIt(SW_DUPLICATE_CREATE);
		}
		byte[]buffer=apdu.getBuffer();
		byte create_length=buffer[ISO7816.OFFSET_LC];
	    byte byteLength=(byte)(apdu.setIncomingAndReceive());
		if((create_length !=0X02)||(byteLength!=0x02))
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		Data=Util.getShort(buffer,ISO7816.OFFSET_CDATA);//
		DataBuffer=new byte[Data];
		
	}
	private void readData(APDU apdu)
	{
		if(DataBuffer == null)
		{
			ISOException.throwIt(SW_CREATE_REQUIRED);
		}
		byte[] buffer=apdu.getBuffer();
		byte read_length=buffer[ISO7816.OFFSET_LC];
		byte byteLength1=(byte)(apdu.setIncomingAndReceive());
		if((read_length !=0X02)||(byteLength1!=0x02))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		short p1p2=Util.getShort(buffer,ISO7816.OFFSET_P1);
		short Data1=Util.getShort(buffer,ISO7816.OFFSET_CDATA);
		if((short)(p1p2+Data1)>Data)
		{
			ISOException.throwIt(SW_READING_OUTOF_BOUNDS);
		}
		
		//short read_data=apdu.setOutgoing();
		Util.arrayCopyNonAtomic(DataBuffer,p1p2,buffer,(short)0,Data1);
		apdu.setOutgoingAndSend((short)0,Data1);
			
	}
	private void writeData(APDU apdu)
	{
		if(DataBuffer==null)
		{
			ISOException.throwIt(SW_CREATE_REQUIRED);
		}
		byte[] buffer=apdu.getBuffer();
		short p1p2=Util.getShort(buffer,ISO7816.OFFSET_P1);
		byte write_length=buffer[ISO7816.OFFSET_LC];
		byte byteLength2=(byte)(apdu.setIncomingAndReceive());
		if(write_length!=byteLength2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		short Data2=Util.getShort(buffer,ISO7816.OFFSET_CDATA);
		if((short)(p1p2+write_length)>Data)
		{
			ISOException.throwIt(SW_WRITING_OUTOF_BOUNDS);
		}
			
		Util.arrayCopyNonAtomic(buffer,(short)0x05,DataBuffer,p1p2,write_length);
			
			
	}
	private void release(APDU apdu)
	{
	
		byte[] buffer=apdu.getBuffer();
		short p1p2=Util.getShort(buffer,ISO7816.OFFSET_P1);
		if(p1p2!=0)
		{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		DataBuffer=null;
		JCSystem.requestObjectDeletion();
	}
}
