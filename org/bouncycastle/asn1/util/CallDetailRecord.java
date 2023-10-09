package org.bouncycastle.asn1.util;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Arrays;

import org.apache.hadoop.io.Writable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DERSequence;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;


public class CallDetailRecord extends ASN1Object implements Writable {
    private static String   cTBCDSymbolString = "0123456789*#abc";
    private static char[]   cTBCDSymbols = cTBCDSymbolString.toCharArray();

    private String message;
    private JSONObject json = new JSONObject();
    private JSONArray array = new JSONArray();
    private JSONObject item = new JSONObject();
    ASN1Sequence cdr;

    public CallDetailRecord() {
        clearFields();
    }

    public CallDetailRecord(ASN1Sequence inSeq) throws UnsupportedEncodingException {

        cdr = inSeq;
        
        for (@SuppressWarnings("unchecked") Enumeration<ASN1Encodable> en = cdr.getObjects(); en.hasMoreElements();) {
            ASN1Encodable em = en.nextElement();
            ASN1Primitive emp = em.toASN1Primitive();
            ASN1TaggedObject o = (ASN1TaggedObject)emp;
            ASN1Primitive val=o.getObject();
            int tag=o.getTagNo();

//          json format
            switch (tag) {
// 
                case 3:
                //TBCD-STRING
                
                    ASN1OctetString oct = (ASN1OctetString)val;
                    
                    try {
                        json.put("servedIMSI",toTBCD(oct.getOctets()));
                    }catch(JSONException e ){}

                break;
                
                case 4:
                //OCTET-STRING
                    
                    ASN1TaggedObject gwaddress = (ASN1TaggedObject)val;
                    switch (gwaddress.getTagNo()) {
                            
                        case 0:
                            try {
                                json.put("p-GWAddress",convertHexToIPAddr(gwaddress.retString()));
                            }catch(JSONException e ){}

                        break;
                        
                        default: break;
                    }
                                
                break;
                            
                case 5:
                //INTEGER
                    try {
                        json.put("chargingID",hexaStringToInteger(val.toString()));
                    }catch(JSONException e ){}

                break;

                case 20:
                
                    try {
                        json.put("localSequenceNumber",hexToDecimal(val.toString()));
                    }catch(JSONException e ){}

                break;
      
                case 22:
                
                    try {
                        json.put("servedMSISDN",hexToDecimal(val.toString()));
                    }catch(JSONException e ){}

                break;
                
                case 32:
                  
                    try {
                        json.put("userLocationInformation", locationUser(val.toString()));
                    }catch(JSONException e ){}

                break;
                
                case 34:
                    if(val instanceof DLSequence){
                        ASN1Sequence seq1 = (ASN1Sequence)o.getObject();

                        for (@SuppressWarnings("unchecked") Enumeration<ASN1Encodable> en1 = seq1.getObjects(); en1.hasMoreElements();) {
                            ASN1Encodable em1 = en1.nextElement();
                            ASN1Primitive emp1 = em1.toASN1Primitive();
                            DERSequence seq=(DERSequence)emp1;
                            
                            JSONObject item1 = new JSONObject();
                            
                            for (@SuppressWarnings("unchecked") Enumeration<ASN1Encodable> en12 = seq.getObjects(); en12.hasMoreElements();) {
                                ASN1Encodable em12 = en12.nextElement();
                                ASN1Primitive emp12 = em12.toASN1Primitive();
                                ASN1TaggedObject o12 = (ASN1TaggedObject)emp12;
                                ASN1Primitive val12=o12.getObject();
                                int tagg2=o12.getTagNo();
                                
                                switch (tagg2) {

                                    case 5:
                                        try {
                                            item1.put("timeOfFirstUsage",convertHexToTimelineString(val12.toString()));
                                        }catch(JSONException e ){}

                                    break; 
                
                                    case 6:
                                        try {
                                            item1.put("timeOfLastUsage",convertHexToTimelineString(val12.toString()));
                                        }catch(JSONException e ){}

                                    break;
                                      
                                    case 12:
                                        try {
                                            item1.put("datavolumeFBCUplink",hexToDecimal(val12.toString()));
                                        }catch(JSONException e ){}

                                    break;
                                            
                                    case 13:
                                        try {
                                            item1.put("datavolumeFBCDownlink",hexToDecimal(val12.toString()));
                                        }catch(JSONException e ){}

                                    break;
                                 
                                    case 17:
                                        try {
                                            item1.put("serviceIdentifier",hexToDecimal(val12.toString()));
                                        }catch(JSONException e ){}

                                    break;
        
                                    default: break;                                
                                }
                                
                            }array.put(item1);
                        }
                    }

                    if(val instanceof DERSequence ){
                        ASN1Sequence seq1 = (ASN1Sequence)o.getObject();
                        for (@SuppressWarnings("unchecked") Enumeration<ASN1Encodable> en1 = seq1.getObjects(); en1.hasMoreElements();) {
                            ASN1Encodable em1 = en1.nextElement();
                            ASN1Primitive emp1 = em1.toASN1Primitive();
                            ASN1TaggedObject o1 = (ASN1TaggedObject)emp1;
                            ASN1Primitive val1=o1.getObject();
                            int tag1=o1.getTagNo();
        
                            switch (tag1) {
    
                                case 5:
                                    
                                    try {
                                        item.put("timeOfFirstUsage",convertHexToTimelineString(val1.toString()));
                                    }catch(JSONException e ){}

                                break; 
                                            
                                case 6:
                                    
                                    try {
                                        item.put("timeOfLastUsage",convertHexToTimelineString(val1.toString()));
                                    }catch(JSONException e ){}

                                break;
                                
                                case 12:
                                    
                                    try {
                                        item.put("datavolumeFBCUplink",hexToDecimal(val1.toString()));
                                    }catch(JSONException e ){}

                                break;
                                            
                                case 13:
                                    
                                    try {
                                        item.put("datavolumeFBCDownlink",hexToDecimal(val1.toString()));
                                    }catch(JSONException e ){}

                                break;
                                
                                case 17:
                                    
                                    try {
                                        item.put("serviceIdentifier",hexToDecimal(val1.toString()));
                                    }catch(JSONException e ){}

                                break; 
                                
                                default: break;
                            }
                        }array.put(item);
                    }
                                
                    if(!(val instanceof DERSequence) && !(val instanceof DLSequence)){
                        ASN1Sequence seq1 = (ASN1Sequence)o.getObject();
                        for (@SuppressWarnings("unchecked") Enumeration<ASN1Encodable> en1 = seq1.getObjects(); en1.hasMoreElements();) {
                            ASN1Encodable em1 = en1.nextElement();
                            ASN1Primitive emp1 = em1.toASN1Primitive();
                            ASN1TaggedObject o1 = (ASN1TaggedObject)emp1;
                            ASN1Primitive val1=o1.getObject();
                            int tagg=o1.getTagNo();
                                
                            switch (tagg) {

                                    case 5:
                                    
                                        try {
                                            item.put("timeOfFirstUsage",convertHexToTimelineString(val1.toString()));
                                        }catch(JSONException e ){}

                                    break; 
                                            
                                    case 6:
                                    
                                        try {
                                            item.put("timeOfLastUsage",convertHexToTimelineString(val1.toString()));
                                        }catch(JSONException e ){}

                                    break;

                                    case 12:
                                    
                                        try {
                                            item.put("datavolumeFBCUplink",hexToDecimal(val1.toString()));
                                        }catch(JSONException e ){}

                                    break;
                                            
                                    case 13:
                                    
                                        try {
                                            item.put("datavolumeFBCDownlink",hexToDecimal(val1.toString()));
                                        }catch(JSONException e ){}

                                    break;
                                        
                                    case 17:
                                    
                                        try {
                                            item.put("serviceIdentifier",hexToDecimal(val1.toString()));
                                        }catch(JSONException e ){}

                                    break;
                                                
                                    default: break;
                                }
                            }array.put(item);
                        }
                    
                    try{
                        json.put("listOfServiceData", array);
                    }catch(JSONException e){}
                         
                break; 

                case 38:
                
                    try {
                        json.put("startTime",convertHexToTimelineString(val.toString()));
                    }catch(JSONException e ){}

                break;
                
                case 39:
                
                    try {
                        json.put("stopTime",convertHexToTimelineString(val.toString()));
                    }catch(JSONException e ){}

                break;

                case 41:
                //INTEGER
                
                    try {
                        json.put("pDNConnectionID",hexaStringToInteger(val.toString()));
                    }catch(JSONException e ){}

                break;

                default: break;
            }
        }
        
        message = json.toString();
    }    

    public void clearFields() {
        //postavi se na null, 0
        //ova treba dopolnitelno da se doraboti
    }
    
    public String getJsonMessage() {
        return message;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return null; //Once we have read in the original ASN.1 we are done with it.
    }

    @Override
    public void readFields(DataInput in) throws IOException {
/*
		recordNumber = in.readInt();
		callingNumber = in.readUTF();
		calledNumber = in.readUTF();
		startDate = in.readUTF();
		startTime = in.readUTF();
		duration = in.readInt();*/

    }

    @Override
    public void write(DataOutput out) throws IOException {
/*	
            out.writeInt(recordNumber);
            out.writeUTF(callingNumber);  //writeUTF includes length info
            out.writeUTF(calledNumber);
            out.writeUTF(startDate);
            out.writeUTF(startTime);
            out.writeInt(duration);*/

    }

    public static String toTBCD (byte[] tbcd) {
        int size = (tbcd == null ? 0 : tbcd.length);
        StringBuffer buffer = new StringBuffer(2*size);
        for (int i=0; i<size; ++i) {
            int octet = tbcd[i];
            int n2 = (octet >> 4) & 0xF;
            int n1 = octet & 0xF;
            if (n1 == 15) {
                throw new NumberFormatException("Illegal filler in octet n=" + i);
            }
            buffer.append(cTBCDSymbols[n1]);
                if (n2 == 15) {
                    if (i != size-1)
                        throw new NumberFormatException("Illegal filler in octet n=" + i);
                } else
                    buffer.append(cTBCDSymbols[n2]);
        }
        
        return buffer.toString();
    }

    public String convertHexToIPAddr(String hex){
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();
        for( int i=0; i<hex.length()-1; i+=2 ){
            String output = hex.substring(i, (i + 2));
            int decimal = Integer.parseInt(output, 16);
            sb.append((char)decimal);
            temp.append(decimal);
            temp.append(".");
        }
        String ip= temp.toString();
        ip = ip.substring(0,ip.length()-1);
        
        return ip;
    }
        
    public String convertHexToIA5String(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i+=2) {
            String str = hex.substring(i, i+2);
            output.append((char)Integer.parseInt(str, 16));
        }
    
        return output.toString();
    }
        
    public String convertHexToBoolean(String hex, int numOfBits){
        int value = Integer.parseInt(hex, 16);
        boolean[] booleans = new boolean[numOfBits];
        StringBuilder temp = new StringBuilder();
        for (int i = 0; i < numOfBits; i++) {
            temp.append((value & 1 << i) != 0);
            temp.append(" ");
        }
        
        return temp.toString();
    }
        
    // y - godina, m - mesec, d - den, h - cas, i - minuti, s - sekundi, sign - znak (2b e +, 2d e minus)
    public String convertHexToTimelineString(String hex){
        String y = hex.substring(0,2);
        String m = hex.substring(2,4);
        String d = hex.substring(4,6);
        String h = hex.substring(6,8);
        String i = hex.substring(8,10);
        String s = hex.substring(10,12);
        String sign = hex.substring(12,14);
        String hh = hex.substring(14,16);
        String mm = hex.substring(16,18);

        sign = (sign.equals("2b")) ?  "+" : "-";
        
        return "20"+y.concat("-"+m).concat("-"+d).concat(" "+h).concat(":"+i).concat(":"+s).concat(" "+sign).concat(""+hh).concat(" "+mm);
    }
        
    public static int hexToDecimal(String s) {
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase();
        int val = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
        
        return val;
    }
    
    private int hexaStringToInteger(String input){
        int res = 0;
        int length = input.length()-2;
        for(int i=0;i<length+1;i++){
            char currNumber = input.charAt(i);
            switch (currNumber){
                case 'a':
                    res += 10 * Math.pow(16,length-i);
                    break;
                case 'b':
                    res += 11 * Math.pow(16,length-i);
                    break;
                case 'c':
                    res += 12 * Math.pow(16,length-i);
                    break;
                case 'd':
                    res += 13 * Math.pow(16,length-i);
                    break;
                case 'e':
                    res += 14 * Math.pow(16,length-i);
                    break;
                case 'f':
                    res += 15 * Math.pow(16,length-i);
                    break;
                default:
                    int number = Integer.parseInt(currNumber + "");
                    res += number * Math.pow(16,length-i);
                    break;
            }
        }
        return res;
    }
    
    private int hexStringToInteger(String input){
        int res = 0;
        int length = input.length()-1;
        for(int i=0;i<length+1;i++){
            char currNumber = input.charAt(i);
            switch (currNumber){
                case 'a':
                    res += 10 * Math.pow(16,length-i);
                    break;
                case 'b':
                    res += 11 * Math.pow(16,length-i);
                    break;
                case 'c':
                    res += 12 * Math.pow(16,length-i);
                    break;
                case 'd':
                    res += 13 * Math.pow(16,length-i);
                    break;
                case 'e':
                    res += 14 * Math.pow(16,length-i);
                    break;
                case 'f':
                    res += 15 * Math.pow(16,length-i);
                    break;
                default:
                    int number = Integer.parseInt(currNumber + "");
                    res += number * Math.pow(16,length-i);
                    break;
            }
        }
        return res;
    }
    
    public String locationUser(String input){
      
      String bazna = input.substring(input.length()-4, input.length()-2);
      String sektor = input.substring(input.length()-2);

      int bazna_hex = hexStringToInteger(bazna);
      int sektor_hex = hexStringToInteger(sektor);
      
      String a = String.valueOf(bazna_hex).concat("-");
      
      return a.concat(String.valueOf(sektor_hex));
    
    }
        
    public String getPdpType(String hex){
        String org = hex.substring(0,2);
        String number = hex.substring(2,4);
        switch (org) {
            case "00": 
            
                org = "pdpOrganize=00(ETSI); ";
                
            break;
            
            case "01":
            
                org = "pdpOrganize=01(IETF); ";
                
            break;
            
            default: break;
        }
            
        switch (number) {
        
            case "00": 
            
                number = "pdpNumber=X.25";
                
            break;
            
            case "01":
            
                number = "pdpNumber=PPP";
                
            break;
            
            case "02":
            
                number = "pdpNumber=OSP:IHOSS";
                
            break;
                
            case "21":
            
                number = "pdpNumber=Ipv4";
                
            break;
            
            case "57":
            
                number = "pdpNumber=Ipv6";
                
            break;
            
            case "8d":
            
                number = "pdpNumber=Ipv4 / Ipv6";
                
            break;
            
            default: break;
                    
        }
        
        return org.concat(number);
    }
}
