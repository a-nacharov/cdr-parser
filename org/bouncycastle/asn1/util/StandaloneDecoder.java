package org.bouncycastle.asn1.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Set;

import org.bouncycastle.asn1.util.CallDetailRecord;

public class StandaloneDecoder {

    public StandaloneDecoder(String filename) throws IOException {
    
        File fileIn = new File(filename);
        FileInputStream fin = new FileInputStream(fileIn);
        InputStream is=decompressStream(fin);
        
        ASN1InputStream asnin = new ASN1InputStream(is);
        ASN1Primitive obj = null;
        String json="[";
        
        while ((obj = asnin.readObject()) != null) {
            if (obj instanceof ASN1Sequence){
                CallDetailRecord thisCdr = new CallDetailRecord((ASN1Sequence) obj);
            }

            else if (obj instanceof ASN1TaggedObject){
                ASN1TaggedObject o = (ASN1TaggedObject)obj;
                
                if(o.getTagNo()==79){

                    ASN1Sequence seq = (ASN1Sequence)o.getObject();
                    CallDetailRecord thisCdr = new CallDetailRecord(seq);

                    
                    json = json + thisCdr.getJsonMessage();
                    json = json + ","+System.lineSeparator();
                }
            }
            else if (obj instanceof ASN1Set){
                System.out.println((ASN1Set)obj);
            }
        }
        if (json != null && json.length() > 0 && json.charAt(json.length() - 2) == ',') {
            json = json.substring(0,json.length()-2);
        }
        if (json != null && json.length() > 0 && json.charAt(json.length() - 1) == ',') {
            json = json.substring(0,json.length()-1);
        }
        json = json +"]";
        System.out.println(json);
        asnin.close();
        is.close();
        fin.close();
    }

    public static InputStream decompressStream(InputStream input) {
        InputStream returnStream=null;
        org.apache.commons.compress.compressors.CompressorInputStream cis = null;
        BufferedInputStream bis=null;
        try {
            bis = new BufferedInputStream(input);
            bis.mark(1024);   //Mark stream to reset if uncompressed data
            cis = new org.apache.commons.compress.compressors.CompressorStreamFactory().createCompressorInputStream(bis);
            returnStream = cis;
        } catch (org.apache.commons.compress.compressors.CompressorException ce) { //CompressorStreamFactory throws CompressorException for uncompressed files
            try {
                bis.reset();
            } catch (IOException ioe) {
                String errmessageIOE="IO Exception ( "+ioe.getClass().getName()+" ) : "+ioe.getMessage();
                System.out.println(errmessageIOE);
            }
            returnStream = bis;
        } catch (Exception e) {
            String errmessage="Exception ( "+e.getClass().getName()+" ) : "+e.getMessage();
            System.out.println(errmessage);
        }
        
        return returnStream;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 ) {
            System.out.println("Missing a filename. Exiting.");
            System.exit(1);
        }

        String filename = args[0];
        try {
            @SuppressWarnings("unused")
            StandaloneDecoder mainObj = new StandaloneDecoder(filename);
        } catch (IOException ioe) {
            String errmessage="ERROR. EXITING. Exception ( "+ioe.getClass().getName()+" ) : "+ioe.getMessage();
            System.out.println(errmessage);
            ioe.printStackTrace();
            System.exit(1);
        }
    }
}
