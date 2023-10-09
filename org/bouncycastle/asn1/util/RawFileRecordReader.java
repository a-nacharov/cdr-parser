package org.bouncycastle.asn1.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.CallDetailRecord;

/**
 * 
 * Input Format for "Simple Generic CDR" with the base data container as Writable
 * Reads in entire ASN.1 file as key.
 * 
 * Outputs Key of startDate and Value of Writable CallDetailRecord
 * 
 * @author awcoleman
 * @version 20140702
 * license: Apache License 2.0; http://www.apache.org/licenses/LICENSE-2.0
 * 
 */
public class RawFileRecordReader extends RecordReader<Text, CallDetailRecord> {

	private Path path;
	private InputStream is;
	private FSDataInputStream fsin;
	private ASN1InputStream asnin;
	private ASN1Primitive obj;
	
	private Text currentKey;
	private CallDetailRecord currentValue;
	private boolean isProcessed = false;

	int recordCounter;


	@Override
	public boolean nextKeyValue() throws IOException, InterruptedException {
		
		if (isProcessed) return false;
		
		if ((obj = asnin.readObject()) != null) {
			
			CallDetailRecord thisCdr = new CallDetailRecord((ASN1Sequence) obj);
			recordCounter++;
			
			currentKey = new Text( thisCdr.getStartDate() );
			currentValue = thisCdr;
			
			return true;
		} else {
			isProcessed = true;
			return false;
		}

	}

	@Override
	public Text getCurrentKey() throws IOException, InterruptedException {
		return currentKey;
	}

	@Override
	public CallDetailRecord getCurrentValue() throws IOException, InterruptedException {
		return currentValue;
	}

	@Override
	public float getProgress() throws IOException, InterruptedException {
		return isProcessed ? 1 : 0;
	}

	@Override
	public void initialize(InputSplit split, TaskAttemptContext context)
			throws IOException, InterruptedException {
		Configuration conf = context.getConfiguration();
		path = ((FileSplit) split).getPath();
		FileSystem fs = path.getFileSystem(conf);
		FSDataInputStream fsin = fs.open(path);
		is=decompressStream(fsin);
		asnin = new ASN1InputStream(is);
		
		recordCounter = 0;
	}

	@Override
	public void close() throws IOException {
		asnin.close();
		is.close();
		if (fsin!=null) fsin.close();
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
}
